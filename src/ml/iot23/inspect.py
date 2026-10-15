"""Read acquired snapshots, reconstruct flows, and fail closed on admission gaps."""

import hashlib
import json
import math
import statistics
import struct
from collections import Counter
from dataclasses import asdict
from itertools import pairwise
from pathlib import Path

from ml.ctu13.flows import Flows
from ml.ctu13.pcap import PcapReader, parse_packet
from ml.iot23.integrity import admission, verify_acquisition, verify_manifest
from ml.iot23.zeek import bind, load
from ml.verified_producers.contracts import digest
from ml.verified_producers.network import Packet
from ml.verified_producers.network_v1_1 import (
    feature_contract,
    network_features,
    producer_contract,
)


def independent_reference(packets: tuple[Packet, ...]) -> tuple[float, ...]:
    """Separate two-pass statistics/reference sums, no producer call."""
    first = packets[0]
    forward = tuple(p for p in packets if p.endpoints == first.endpoints)
    backward = tuple(p for p in packets if p.endpoints != first.endpoints)
    lengths = tuple(p.ip_length for p in packets)
    intervals = tuple(
        (b.timestamp_ns - a.timestamp_ns) / 1_000_000_000 for a, b in pairwise(packets)
    )
    values = (
        (packets[-1].timestamp_ns - first.timestamp_ns) / 1_000_000_000,
        len(forward),
        len(backward),
        sum(p.ip_length for p in forward),
        sum(p.ip_length for p in backward),
        min(lengths),
        max(lengths),
        float(statistics.mean(lengths)),
        float(statistics.pstdev(lengths)),
        sum(1 for p in packets if p.tcp_flags & 2),
        sum(1 for p in packets if p.tcp_flags & 1),
        sum(1 for p in packets if p.tcp_flags & 4),
        statistics.mean(intervals) if intervals else 0.0,
        max(intervals) if intervals else 0.0,
    )
    return tuple(struct.unpack("!f", struct.pack("!f", v))[0] for v in values)


def verify_reference(
    packets: tuple[Packet, ...], document: dict[str, object], source_identity: str
) -> None:
    vector = network_features(
        packets, source_origin="OFFLINE_PCAP", source_identity=source_identity
    )
    if document != reference_document(packets, source_identity) or any(
        not math.isclose(a, b, rel_tol=1e-6, abs_tol=1e-7)
        for a, b in zip(vector.values, independent_reference(packets), strict=True)
    ):
        raise ValueError("ACTUAL_REFERENCE_TAMPERED_OR_MISMATCH")


def reference_document(
    packets: tuple[Packet, ...], source_identity: str
) -> dict[str, object]:
    vector = network_features(
        packets, source_origin="OFFLINE_PCAP", source_identity=source_identity
    )
    return {
        "source_identity": source_identity,
        "source_origin": "OFFLINE_PCAP",
        "producer_version": "1.1.0",
        "configuration_digest": digest(producer_contract()),
        "contract_digest": digest(feature_contract()),
        "source_digest": vector.source_digest,
        "feature_digest": vector.feature_digest,
        "feature_names": list(vector.feature_names),
        "expected_values": list(independent_reference(packets)),
        "reference_method": "statistics.mean/pstdev; integer counters; independent two-pass; final float32",
        "packet_metadata_digest": digest([asdict(p) for p in packets]),
        "packet_count": len(packets),
        "packet_lengths": [p.ip_length for p in packets],
        "flags": [p.tcp_flags for p in packets],
        "timestamp_offsets_ns": [
            p.timestamp_ns - packets[0].timestamp_ns for p in packets
        ],
        "first_observed_direction": [
            p.endpoints == packets[0].endpoints for p in packets
        ],
        "artifact_binding": "NONE_NEW_MODEL_NOT_TRAINED",
        "training_native_parity": "NOT_VERIFIED",
    }


def _chunks(path: Path):
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            yield chunk


def file_sha256(path: Path) -> str:
    sha = hashlib.sha256()
    for chunk in _chunks(path):
        sha.update(chunk)
    return sha.hexdigest()


def inspect_session(
    root: Path, raw: dict[str, object], label: dict[str, object]
) -> tuple[dict[str, object], list[dict[str, object]]]:
    path = root / raw["relative_path"]
    if (
        path.is_symlink()
        or path.stat().st_size != raw["size_bytes"]
        or file_sha256(path) != raw["sha256"]
    ):
        raise ValueError("RAW_DIGEST_MISMATCH")
    labels = load(root / label["relative_path"], label["sha256"], raw["sha256"])
    reader = PcapReader(_chunks(path))
    flows = Flows()
    counts = Counter()
    errors = Counter()
    statuses = Counter()
    rows = []
    references = []
    starts = []
    ends = []
    origins = set()
    duplicates = set()
    seen_flows = set()
    min_ns = max_ns = None

    def consume(flow):
        counts["reconstructed_flows"] += 1
        counts["closure:" + flow.closure] += 1
        status, connection, reason = bind(flow.packets, labels)
        if flow.incomplete:
            status, reason = "EXCLUDED", flow.reason
        first = flow.packets[0]
        fingerprint = digest(
            [
                (p.timestamp_ns, p.endpoints, p.transport, p.ip_length, p.tcp_flags)
                for p in flow.packets
            ]
        )
        if fingerprint in seen_flows:
            duplicates.add(fingerprint)
            status, reason = "EXCLUDED", "DUPLICATE_FLOW"
        seen_flows.add(fingerprint)
        vector = None
        if status == "VERIFIED_MATCH":
            vector = network_features(
                flow.packets,
                source_origin="OFFLINE_PCAP",
                source_identity=raw["sha256"],
            )
            if not references and len(flow.packets) >= 2:
                ref = reference_document(flow.packets, raw["sha256"])
                verify_reference(flow.packets, ref, raw["sha256"])
                references.append(ref)
        row = {
            "flow_id": flow.flow_id,
            "raw_fingerprint": fingerprint,
            "status": status,
            "reason": reason,
            "closure": flow.closure,
            "label_reference": connection.reference if connection else None,
            "zeek_uid_digest": digest(connection.uid) if connection else None,
            "label": connection.label if connection else None,
            "detailed_label": connection.detailed if connection else None,
            "start_ns": first.timestamp_ns,
            "end_ns": flow.packets[-1].timestamp_ns,
            "first_seen_vs_zeek": "ORIG"
            if connection and first.endpoints[0] == connection.orig
            else "RESP"
            if connection
            else "UNKNOWN",
            "uid_reconstructed_from_pcap": False,
            "source_origin": "OFFLINE_PCAP",
            "source_file_sha256": raw["sha256"],
            "source_digest": vector.source_digest if vector else None,
            "feature_digest": vector.feature_digest if vector else None,
            "values": list(vector.values) if vector else None,
        }
        rows.append(row)
        if connection:
            origins.add(digest(connection.orig[0]))
        starts.append(first.timestamp_ns)
        ends.append(flow.packets[-1].timestamp_ns)

    for record in reader:
        counts["raw_packets"] += 1
        min_ns = (
            record.timestamp_ns if min_ns is None else min(min_ns, record.timestamp_ns)
        )
        max_ns = (
            record.timestamp_ns if max_ns is None else max(max_ns, record.timestamp_ns)
        )
        if record.captured_length < record.wire_length:
            counts["snaplen_truncated_packets"] += 1
        try:
            packet = parse_packet(record, raw["sha256"])
        except ValueError as exc:
            errors[str(exc)] += 1
            continue
        counts["parsed_packets"] += 1
        counts["transport:" + packet.transport] += 1
        counts["ip:IPv6" if ":" in packet.source_address else "ip:IPv4"] += 1
        try:
            closed = flows.add(packet)
        except ValueError as exc:
            errors[str(exc)] += 1
            # A missing packet is a local capture-quality gap for active windows.
            for flow in flows.mark_gap():
                consume(flow)
            continue
        for flow in closed:
            consume(flow)
    for flow in flows.finish(complete=True):
        consume(flow)
    # A Zeek connection spanning several producer segments is never silently 1:1.
    label_uses = Counter(r["label_reference"] for r in rows if r["label_reference"])
    for row in rows:
        if row["status"] == "VERIFIED_MATCH" and label_uses[row["label_reference"]] > 1:
            row.update(
                status="CANDIDATE_MATCH",
                reason="MULTIPLE_SEGMENTS_PER_ZEEK_CONNECTION",
                values=None,
                feature_digest=None,
            )
    distribution = Counter()
    reasons = Counter()
    for row in rows:
        statuses[row["status"]] += 1
        reasons[row["reason"]] += 1
        if row["status"] == "VERIFIED_MATCH":
            distribution[row["label"]] += 1
    report = {
        "session": raw["capture_session"],
        "raw_sha256": raw["sha256"],
        "label_sha256": label["sha256"],
        "pcap": {
            "format": reader.format,
            "endian": reader.endian,
            "timestamp_ns_per_tick": reader.factor,
            "snaplen": reader.snaplen,
            "link_type": 1,
            "sha256_during_full_stream": reader.reader.sha.hexdigest(),
            "stream_bytes": reader.reader.bytes_read,
        },
        "counts": dict(counts),
        "parser_exclusions": dict(errors),
        "flow_state_reasons": dict(flows.reason_counts),
        "peak_retained_state_bytes": flows.peak_state_bytes,
        "label_counts": labels.counts,
        "label_schema_digest": labels.schema_digest,
        "binding_status": {
            k: statuses[k]
            for k in (
                "VERIFIED_MATCH",
                "CANDIDATE_MATCH",
                "AMBIGUOUS",
                "UNMATCHED",
                "EXCLUDED",
            )
        },
        "binding_reasons": dict(reasons),
        "verified_class_distribution": dict(distribution),
        "duplicate_flow_count": len(duplicates),
        "multi_segment_label_count": sum(n > 1 for n in label_uses.values()),
        "time_range_ns": [min_ns, max_ns],
        "label_epoch_range_ns": [
            min(r.start_ns for rs in labels.rows.values() for r in rs),
            max(r.end_ns or r.start_ns for rs in labels.rows.values() for r in rs),
        ],
        "observed_origin_address_hashes": sorted(origins),
        "capture_drop_count": "UNKNOWN",
        "capture_quality": "UNKNOWN",
        "actual_reference_pairs": references,
        "training_operational_parity": "NOT_VERIFIED",
        "admitted_samples": 0,
    }
    if report["pcap"]["sha256_during_full_stream"] != raw["sha256"]:
        raise ValueError("STREAM_INTEGRITY_FAILED")
    return report, rows


def inspect(root: Path, output: Path) -> dict[str, object]:
    acquisition = json.loads((root / "acquisition.json").read_text())
    plan = json.loads(
        (
            Path(__file__).resolve().parents[3]
            / "docs/network-training-download-plan.json"
        ).read_text()
    )
    verify_acquisition(acquisition, plan)
    if (
        acquisition["status"] != "DOWNLOADED_NOT_ADMITTED"
        or len(acquisition["files"]) != 6
    ):
        raise ValueError("ACQUISITION_INCOMPLETE")
    if output.exists():
        raise FileExistsError("INSPECTION_ALREADY_EXISTS")
    output.mkdir(mode=0o700)
    reports = []
    for sid in ("8-1", "20-1", "34-1"):
        session = "CTU-IoT-Malware-Capture-" + sid
        files = [r for r in acquisition["files"] if r["capture_session"] == session]
        report, rows = inspect_session(
            root,
            next(f for f in files if f["role"] == "PCAP"),
            next(f for f in files if f["role"] == "ZEEK_LABELED_FLOW"),
        )
        with (output / (sid + "-flows.jsonl")).open("x") as stream:
            for row in rows:
                stream.write(json.dumps(row, sort_keys=True) + "\n")
        report["flow_records_sha256"] = hashlib.sha256(
            (output / (sid + "-flows.jsonl")).read_bytes()
        ).hexdigest()
        reports.append(report)
        print(
            session,
            report["counts"]["raw_packets"],
            report["binding_status"],
            flush=True,
        )
    overlaps = {}
    fingerprints = {}
    feature_values = {}
    for sid in ("8-1", "20-1", "34-1"):
        data = [
            json.loads(line)
            for line in (output / (sid + "-flows.jsonl")).read_text().splitlines()
        ]
        fingerprints[sid] = {r["raw_fingerprint"] for r in data}
        feature_values[sid] = {
            digest(r["values"]) for r in data if r["status"] == "VERIFIED_MATCH"
        }
    duplicate_cross = {
        a + " / " + b: len(fingerprints[a] & fingerprints[b])
        for a, b in (("8-1", "20-1"), ("8-1", "34-1"), ("20-1", "34-1"))
    }
    vector_collisions = {
        a + " / " + b: len(feature_values[a] & feature_values[b])
        for a, b in (("8-1", "20-1"), ("8-1", "34-1"), ("20-1", "34-1"))
    }
    for i, left in enumerate(reports):
        for right in reports[i + 1 :]:
            overlaps[left["session"] + " / " + right["session"]] = len(
                set(left["observed_origin_address_hashes"])
                & set(right["observed_origin_address_hashes"])
            )
    result = {
        "contract": "iot23-admission-inspection:v1",
        "acquisition_digest": digest(acquisition),
        "producer_configuration_digest": digest(producer_contract()),
        "feature_contract_digest": digest(feature_contract()),
        "sessions": reports,
        "split": {
            "train": "8-1",
            "validation": "20-1",
            "test": "34-1",
            "status": "BLOCKED",
            "exact_raw_flow_overlap_counts": duplicate_cross,
            "feature_value_collision_counts": vector_collisions,
            "origin_address_overlap_counts": overlaps,
            "physical_host_and_campaign_independence": "UNVERIFIED",
            "test_used_for_model_selection": False,
        },
        "admission": "BLOCKED",
        "admitted_samples": 0,
        "network_quality": "BLOCKED",
        "network_edge": "BLOCKED",
        "operational_input": "NOT_INFERABLE",
        "inference": "BLOCKED",
        "write_disposition": "WRITE_DENIED",
        "blockers": [
            "Capture loss/gap provenance unknown",
            "Physical device/campaign independence not verified",
            "Training-to-native parity pair missing",
            "Train and validation have zero strictly verified malicious flows",
        ],
    }
    gates = {
        k: "PASS"
        for k in (
            "raw_integrity",
            "label_integrity",
            "binding",
            "producer",
            "golden_pair",
            "manifest",
            "label_provenance",
        )
    }
    gates.update(
        split_leakage="UNVERIFIED",
        holdout="BLOCKED_CLASS_COVERAGE",
        capture_quality="UNKNOWN",
    )
    gates["golden_pair"] = (
        "PASS" if all(r["actual_reference_pairs"] for r in reports) else "BLOCKED"
    )
    result["gates"] = gates
    result["admission"] = admission(gates)
    result["manifest_digest"] = digest(result)
    verify_manifest(result)
    (output / "inspection.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    inspect(args.root, args.output)
