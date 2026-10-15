"""Explicit offline inspection. Does not train or enable inference.

python -m ml.ctu13.pilot --root <approved-private-directory>
Expansion is a single bounded pass. A failed expansion never admits a dataset.
"""

import argparse
import hashlib
import json
import os
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from time import monotonic

from ml.ctu13.flows import Flow, Flows
from ml.ctu13.labels import bind, load_labels
from ml.ctu13.pcap import PcapReader, parse_packet
from ml.raw_acquisition.storage import iter_bzip2, private_directory
from ml.verified_producers.contracts import digest
from ml.verified_producers.network_v1_1 import (
    feature_contract,
    network_features,
    producer_contract,
)


def inspect(
    root: Path,
    *,
    label_utc_offset_seconds: int = 7200,
    expansion_budget_bytes: int = 512 * 1024**2,
) -> dict[str, object]:
    """CEST offset is an UNVERIFIED hypothesis, never optimized or admission authority."""
    if (
        type(expansion_budget_bytes) is not int
        or not 1 <= expansion_budget_bytes <= 512 * 1024**2
    ):
        raise ValueError("ARCHIVE_EXPANSION_LIMIT")
    private_directory(root)
    receipts = json.loads((root / "acquisition-receipts.json").read_text())
    required = {
        "capture20110816-2.truncated.pcap.bz2": 111664996,
        "capture20110816-2.binetflow": 15630512,
    }
    if (
        len(receipts) != 2
        or {r["filename"]: r["size_bytes"] for r in receipts} != required
    ):
        raise ValueError("ACQUISITION_IDENTITY_MISMATCH")
    sources = {}
    for receipt in receipts:
        path = root / receipt["filename"]
        if path.is_symlink() or path.stat().st_size != receipt["size_bytes"]:
            raise ValueError("RAW_FILE_INVALID")
        with path.open("rb") as raw_stream:
            sha = hashlib.file_digest(raw_stream, "sha256").hexdigest()
        if sha != receipt["sha256"]:
            raise ValueError("RAW_DIGEST_MISMATCH")
        sources[receipt["filename"]] = sha
    source = sources["capture20110816-2.truncated.pcap.bz2"]
    labels = load_labels(
        root / "capture20110816-2.binetflow",
        label_identity=sources["capture20110816-2.binetflow"],
        session_identity=source,
        utc_offset_seconds=label_utc_offset_seconds,
        clock_verified=False,
    )
    counts = Counter()
    errors = Counter()
    closures = Counter()
    families = Counter()
    protocols = Counter()
    classes = Counter()
    flows = Flows()
    seen_flows = set()
    started = monotonic()
    parser = PcapReader(
        iter_bzip2(
            root / "capture20110816-2.truncated.pcap.bz2",
            max_expanded_bytes=expansion_budget_bytes,
        )
    )
    first_ns = last_ns = None
    reference = None
    complete = False
    failure = None
    # New no-clobber derived output; only schema/features/digests, no addresses/payload.
    output = root / "pilot-candidates.jsonl"
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    dataset_sha = hashlib.sha256()

    def consume(flow: Flow, stream) -> None:
        nonlocal reference
        counts["flows"] += 1
        closures[flow.closure] += 1
        identity = digest([p.event_id for p in flow.packets])
        if identity in seen_flows:
            raise ValueError("DUPLICATE_FLOW")
        if len(seen_flows) >= 1000000:
            raise ValueError("FLOW_COUNT_LIMIT")
        seen_flows.add(identity)
        if flow.closure in ("RESOURCE_EVICTION", "INCOMPLETE_CAPTURE", "PACKET_LIMIT"):
            counts["incomplete_flows"] += 1
            return
        status, label = bind(flow.packets, labels)
        counts[status] += 1
        if label:
            classes[label.classification] += 1
        if status not in ("MATCHED", "CLOCK_UNVERIFIED"):
            return
        vector = network_features(
            flow.packets, source_origin="OFFLINE_PCAP", source_identity=source
        )
        row = {
            "flow_digest": identity,
            "vector": asdict(vector),
            "feature_digest": vector.feature_digest,
            "label_reference": label.reference,
            "label": label.classification,
            "binding_status": status,
            "split_group": source,
            "training_admitted": False,
        }
        encoded = (
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        stream.write(encoded)
        dataset_sha.update(encoded)
        counts["diagnostic_candidate_rows"] += 1
        if reference is None and 2 <= len(flow.packets) <= 32:
            first = flow.packets[0]
            reference = {
                "kind": "ACTUAL_PCAP_DERIVED_REFERENCE_INPUT",
                "source_identity": source,
                "source_digest": vector.source_digest,
                "feature_names": list(vector.feature_names),
                "packet_metadata": [
                    {
                        "relative_ns": p.timestamp_ns - first.timestamp_ns,
                        "ip_length": p.ip_length,
                        "forward": p.endpoints == first.endpoints,
                        "tcp_flags": p.tcp_flags,
                    }
                    for p in flow.packets
                ],
                "values": list(vector.values),
                "feature_digest": vector.feature_digest,
                "independent_reference_status": "PENDING",
                "training_operational_parity": "BLOCKED",
            }

    with os.fdopen(fd, "wb") as stream:
        try:
            for record in parser:
                counts["raw_packets"] += 1
                counts["payload_truncated_records"] += (
                    record.captured_length < record.wire_length
                )
                if first_ns is None:
                    first_ns = record.timestamp_ns
                last_ns = record.timestamp_ns
                try:
                    packet = parse_packet(record, source)
                except ValueError as exc:
                    errors[str(exc)] += 1
                    continue
                counts["parsed_packets"] += 1
                families["IPv6" if ":" in packet.source_address else "IPv4"] += 1
                protocols[packet.transport] += 1
                try:
                    closed = flows.add(packet)
                except ValueError as exc:
                    errors[str(exc)] += 1
                    continue
                for flow in closed:
                    consume(flow, stream)
            complete = True
        except ValueError as exc:
            failure = str(exc)
        for flow in flows.finish(complete=complete):
            consume(flow, stream)
        stream.flush()
        os.fsync(stream.fileno())
    report = {
        "dataset_id": "ctu13-s07-header-pilot-v1",
        "source_files": receipts,
        "counts": dict(counts),
        "parse_exclusions": dict(errors),
        "closures": dict(closures),
        "ip_families": dict(families),
        "protocols": dict(protocols),
        "label_rows": labels.counts,
        "candidate_label_distribution": dict(classes),
        "first_packet_ns": first_ns,
        "last_packet_ns": last_ns,
        "expanded_bytes_read": parser.reader.bytes_read,
        "expanded_sha256": parser.reader.sha.hexdigest()
        if complete
        else "UNKNOWN_INCOMPLETE",
        "archive_integrity": "VERIFIED" if complete else "BLOCKED",
        "archive_failure": failure,
        "pcap_format": {
            "format": parser.format,
            "link_type": "ETHERNET",
            "endian": parser.endian,
            "timestamp_resolution_ns": parser.factor,
            "snaplen": parser.snaplen,
        },
        "label_clock": {
            "offset_seconds_hypothesis": label_utc_offset_seconds,
            "verified": False,
        },
        "producer_version": "1.1.0",
        "producer_config_digest": digest(producer_contract()),
        "feature_contract_digest": digest(feature_contract()),
        "dataset_digest": dataset_sha.hexdigest(),
        "admitted_sample_count": 0,
        "dataset_admission": "BLOCKED",
        "retraining_readiness": "BLOCKED",
        "holdout": "BLOCKED_SINGLE_CAPTURE_SESSION",
        "capture_drop": "UNKNOWN",
        "capture_gap": "UNKNOWN",
        "operational_inference": "NOT_INFERABLE",
        "finding_promotion": "BLOCKED",
        "write": "WRITE_DENIED",
        "elapsed_seconds": monotonic() - started,
        "reference_input": reference,
    }
    report["summary_digest"] = digest(report)
    summary = root / "pilot-summary.json"
    with summary.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    return report


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--root", required=True, type=Path)
    cli.add_argument("--expansion-budget-bytes", type=int, default=512 * 1024**2)
    args = cli.parse_args()
    result = inspect(args.root, expansion_budget_bytes=args.expansion_budget_bytes)
    print(
        json.dumps(
            {k: v for k, v in result.items() if k != "reference_input"}, indent=2
        )
    )
