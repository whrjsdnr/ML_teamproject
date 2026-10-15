"""One verified Producer Flow per row; frozen binding, no operational admission."""

import gc
import json
from collections import Counter
from pathlib import Path

from ml.ctu13.flows import Flows
from ml.ctu13.pcap import PcapReader, parse_packet
from ml.iot23.binding_audit import verify_policy_lock
from ml.iot23.capture3_acquire import verify_receipt
from ml.iot23.inspect import (
    _chunks,
    file_sha256,
    inspect_session,
    reference_document,
    verify_reference,
)
from ml.iot23.integrity import verify_acquisition
from ml.iot23.recovery import policy, recover
from ml.iot23.wire_reference import read_reference
from ml.iot23.zeek import Connection, load
from ml.verified_producers.contracts import NETWORK_NAMES, digest
from ml.verified_producers.network_v1_1 import (
    feature_contract,
    network_features,
    producer_contract,
)

ROLES = {"train": "8-1", "validation": "3-1", "diagnostic": "20-1", "test": "34-1"}


def seal(document: dict) -> dict:
    return {**document, "manifest_digest": digest(document)}


def verify_seal(document: dict) -> None:
    if document.get("manifest_digest") != digest(
        {k: v for k, v in document.items() if k != "manifest_digest"}
    ):
        raise ValueError("MANIFEST_TAMPERED")


def write_new(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")
    path.chmod(0o600)


def acquisition(repo: Path) -> dict[str, tuple[Path, dict, dict]]:
    prior = repo / "data/raw/acquisition/iot23-network14-3sessions-v1"
    newer = repo / "data/raw/acquisition/iot23-capture-3-1-muhstik-v1"
    first = json.loads((prior / "acquisition.json").read_text())
    second = json.loads((newer / "acquisition.json").read_text())
    verify_acquisition(
        first,
        json.loads((repo / "docs/network-training-download-plan.json").read_text()),
    )
    verify_receipt(
        second,
        json.loads((repo / "docs/iot23-capture3-download-plan.json").read_text()),
    )
    verify_policy_lock(
        json.loads((repo / "docs/iot23-binding-recovery-policy-lock.json").read_text())
    )
    result = {}
    for role, suffix in ROLES.items():
        root, receipt = (newer, second) if suffix == "3-1" else (prior, first)
        files = [
            r for r in receipt["files"] if r["capture_session"].endswith("-" + suffix)
        ]
        raw = next(r for r in files if r["role"] == "PCAP")
        label = next(r for r in files if r["role"] != "PCAP")
        for row in (raw, label):
            path = root / row["relative_path"]
            if (
                path.is_symlink()
                or not path.is_file()
                or path.stat().st_size != row["size_bytes"]
                or file_sha256(path) != row["sha256"]
            ):
                raise ValueError("RAW_OR_LABEL_INTEGRITY")
        result[role] = root, raw, label
    return result


def verify_bound_class(bound: list[Connection], expected: str | None) -> None:
    if (
        not bound
        or expected not in {"Benign", "Malicious"}
        or {r.label for r in bound} != {expected}
    ):
        raise ValueError("CONFLICTING_OR_MISSING_VERIFIED_LABEL")


def build_session(
    root: Path, raw: dict, label: dict, role: str
) -> tuple[list[dict], dict]:
    if role not in ROLES or not raw["capture_session"].endswith("-" + ROLES[role]):
        raise ValueError("FIXED_ROLE_MISMATCH")
    baseline, old_rows = inspect_session(root, raw, label)
    old = {r["flow_id"]: r for r in old_rows}
    del old_rows
    wire, _ = read_reference(root / raw["relative_path"], raw["sha256"])
    labels = load(root / label["relative_path"], label["sha256"], raw["sha256"])
    refs_by_id = {r.reference: r for rows in labels.rows.values() for r in rows}
    flows = Flows()
    rows, used_labels, used_packets = [], set(), set()
    statuses, reasons = Counter(), Counter()
    reference_classes = set()

    def consume(flow):
        previous = old[flow.flow_id]
        result = recover(flow, labels, wire)
        status = result.status
        if (
            previous["status"] != "VERIFIED_MATCH"
            and result.reason != "EXACT_SYN_PACKET_PARTITION"
        ):
            status = previous["status"]
        statuses[status] += 1
        if status != "VERIFIED_MATCH":
            reasons[status + ":" + result.reason] += 1
            return
        bound = [refs_by_id[r] for r in result.references]
        verify_bound_class(bound, result.label)
        if used_labels.intersection(result.references) or used_packets.intersection(
            p.event_id for p in flow.packets
        ):
            raise ValueError("DUPLICATE_LABEL_OR_PACKET_TRAINING_UNIT")
        used_labels.update(result.references)
        used_packets.update(p.event_id for p in flow.packets)
        vector = network_features(
            flow.packets, source_origin="OFFLINE_PCAP", source_identity=raw["sha256"]
        )
        if result.label not in reference_classes and len(flow.packets) > 1:
            verify_reference(
                flow.packets,
                reference_document(flow.packets, raw["sha256"]),
                raw["sha256"],
            )
            reference_classes.add(result.label)
        rows.append(
            {
                "role": role,
                "session": raw["capture_session"],
                "flow_id": flow.flow_id,
                "raw_fingerprint": previous["raw_fingerprint"],
                "label_references": list(result.references),
                "y": int(result.label == "Malicious"),
                "values": list(vector.values),
                "feature_digest": vector.feature_digest,
                "feature_values_digest": digest(vector.values),
                "source_digest": vector.source_digest,
                "start_ns": flow.packets[0].timestamp_ns,
                "end_ns": flow.packets[-1].timestamp_ns,
                "endpoint_hashes": [
                    digest(e) for e in sorted(flow.packets[0].endpoints)
                ],
                "address_hashes": [
                    digest(e[0]) for e in sorted(flow.packets[0].endpoints)
                ],
            }
        )

    for record in PcapReader(_chunks(root / raw["relative_path"])):
        try:
            packet = parse_packet(record, raw["sha256"])
        except ValueError:
            continue
        for flow in flows.add(packet):
            consume(flow)
    for flow in flows.finish(complete=True):
        consume(flow)
    rows.sort(key=lambda r: (r["start_ns"], r["flow_id"]))
    if len({r["flow_id"] for r in rows}) != len(rows) or len(
        {r["raw_fingerprint"] for r in rows}
    ) != len(rows):
        raise ValueError("DUPLICATE_RAW_FLOW")
    report = seal(
        {
            "research_only": True,
            "operational_admission": "BLOCKED",
            "role": role,
            "session": raw["capture_session"],
            "raw_sha256": raw["sha256"],
            "label_sha256": label["sha256"],
            "policy_digest": digest(policy()),
            "producer_version": "1.1.0",
            "producer_config_digest": digest(producer_contract()),
            "feature_contract_digest": digest(feature_contract()),
            "feature_names": list(NETWORK_NAMES),
            "dtype": "float32",
            "origin": "OFFLINE_PCAP",
            "raw_packets": baseline["counts"]["raw_packets"],
            "reconstructed_flows": len(old),
            "binding_statuses": dict(statuses),
            "excluded_reasons": dict(reasons),
            "sample_count": len(rows),
            "class_counts": dict(Counter(str(r["y"]) for r in rows)),
            "row_digest": digest(rows),
            "golden_reference_classes": sorted(reference_classes),
            "capture_quality": "UNKNOWN",
            "label_unit": "ONE_VERIFIED_PRODUCER_FLOW_NOT_ZEEK_CONNECTION_COUNT",
        }
    )
    gc.collect()
    return rows, report


def leakage(left: list[dict], right: list[dict]) -> dict:
    result = {}
    for key in (
        "flow_id",
        "raw_fingerprint",
        "label_references",
        "feature_digest",
        "feature_values_digest",
        "endpoint_hashes",
        "address_hashes",
        "session",
    ):

        def values(rows, field=key):
            return {
                v
                for row in rows
                for v in (row[field] if isinstance(row[field], list) else [row[field]])
            }

        result[key + "_overlap"] = len(values(left) & values(right))
    for key in (
        "flow_id",
        "raw_fingerprint",
        "label_references",
        "feature_digest",
        "session",
    ):
        if result[key + "_overlap"]:
            raise ValueError("CONFIRMED_CROSS_SPLIT_LEAKAGE:" + key)
    result["feature_collisions_policy"] = (
        "REPORT_IDENTICAL_VALUES_NOT_PROOF_OF_SAME_RAW_FLOW; NO_TEST_FILTER_TUNING"
    )
    result["host_campaign_independence"] = "UNVERIFIED"
    if left and right:
        a = min(r["start_ns"] for r in left), max(r["end_ns"] for r in left)
        b = min(r["start_ns"] for r in right), max(r["end_ns"] for r in right)
        result["time_overlap"] = not (a[1] < b[0] or b[1] < a[0])
        result["forward_time_order"] = a[1] < b[0]
    return result


def store_split(output: Path, role: str, rows: list[dict], report: dict) -> None:
    with (output / f"{role}.jsonl").open("x") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")
    (output / f"{role}.jsonl").chmod(0o600)
    write_new(output / f"{role}-manifest.json", report)


def load_split(output: Path, role: str) -> tuple[list[dict], dict]:
    report = json.loads((output / f"{role}-manifest.json").read_text())
    verify_seal(report)
    rows = [
        json.loads(line) for line in (output / f"{role}.jsonl").read_text().splitlines()
    ]
    if (
        report.get("producer_version") != "1.1.0"
        or report.get("feature_names") != list(NETWORK_NAMES)
        or report.get("producer_config_digest") != digest(producer_contract())
        or report.get("feature_contract_digest") != digest(feature_contract())
        or report.get("dtype") != "float32"
        or report.get("origin") != "OFFLINE_PCAP"
        or report.get("research_only") is not True
        or report.get("operational_admission") != "BLOCKED"
    ):
        raise ValueError("DATASET_CONTRACT_MISMATCH")
    references = [ref for row in rows for ref in row["label_references"]]
    if len(references) != len(set(references)) or any(
        not row["label_references"]
        or row["feature_values_digest"] != digest(row["values"])
        for row in rows
    ):
        raise ValueError("DUPLICATE_LABEL_OR_FEATURE_INTEGRITY")
    if (
        report["row_digest"] != digest(rows)
        or report["sample_count"] != len(rows)
        or report["role"] != role
        or any(r["role"] != role for r in rows)
    ):
        raise ValueError("DATASET_MANIFEST_MISMATCH")
    return rows, report
