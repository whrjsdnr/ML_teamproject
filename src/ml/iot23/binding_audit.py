"""Finite saved-byte audit: unchanged baseline, independent headers, strict recovery."""

import argparse
import hashlib
import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from ml.ctu13.flows import Flows
from ml.ctu13.pcap import PcapReader, parse_packet
from ml.iot23.inspect import _chunks, inspect_session
from ml.iot23.integrity import verify_acquisition
from ml.iot23.recovery import BindingResult, policy, recover
from ml.iot23.wire_reference import WirePacket, partition_reference, read_reference
from ml.iot23.zeek import load
from ml.verified_producers.contracts import digest
from ml.verified_producers.network_v1_1 import network_features, producer_contract


def categories(refs: tuple[WirePacket, ...]) -> tuple[str, ...]:
    result = []
    if any(r.transport == "udp" for r in refs):
        result.append("UDP")
    if any(r.transport == "tcp" for r in refs):
        result.append("TCP")
    if any(r.flags == 16 and r.payload_length == 0 for r in refs):
        result.append("ACK_ONLY")
    if any(r.flags & 1 for r in refs):
        result.append("FIN")
    if any(r.flags & 4 for r in refs):
        result.append("RST")
    if any(r.flags & 2 for r in refs):
        result.append("SYN")
    seen = set()
    for r in refs:
        key = (r.endpoints, r.sequence, r.flags, r.payload_length, r.payload_sha256)
        if r.transport == "tcp" and (r.payload_length or r.flags & 3) and key in seen:
            result.append("EXACT_SEQUENCE_PAYLOAD_REPEAT")
            break
        seen.add(key)
    sequences = {r.sequence for r in refs if r.flags == 2}
    if len(sequences) > 1:
        result.append("CONNECTION_REUSE_SYN_SEQUENCE_CHANGE")
    return tuple(result)


def audit_session(
    root: Path,
    raw: dict[str, object],
    label: dict[str, object],
    baseline_expected: dict[str, object],
) -> dict[str, object]:
    baseline, old_rows = inspect_session(root, raw, label)
    if baseline != baseline_expected:
        # Stored evidence also includes the external JSONL file checksum.
        expected = {
            k: v for k, v in baseline_expected.items() if k != "flow_records_sha256"
        }
        if baseline != expected:
            raise ValueError("BASELINE_REPRODUCTION_MISMATCH")
    old = {r["flow_id"]: r for r in old_rows}
    wire, reference_counts = read_reference(root / raw["relative_path"], raw["sha256"])
    labels = load(root / label["relative_path"], label["sha256"], raw["sha256"])
    flows = Flows()
    records = []
    examples = {}
    category_counts = Counter()
    taxonomy = Counter()
    counts = Counter()
    strict = Counter()
    classes = Counter()
    label_refs = set()
    seen_packet_refs = set()

    def consume(flow):
        before = old[flow.flow_id]
        result = recover(flow, labels, wire)
        if (
            before["status"] != "VERIFIED_MATCH"
            and result.reason != "EXACT_SYN_PACKET_PARTITION"
        ):
            result = BindingResult(
                before["status"],
                result.reason,
                result.references,
                before["label"],
                "BASELINE",
            )
        if before["status"] == "VERIFIED_MATCH" and result.status != "VERIFIED_MATCH":
            raise ValueError("BASELINE_VERIFIED_REGRESSION")
        refs = tuple(wire[int(p.event_id.rsplit(":", 1)[1])] for p in flow.packets)
        tags = categories(refs)
        category_counts.update(tags)
        if result.status == "AMBIGUOUS":
            tags = (*tags, "AMBIGUOUS_BINDING")
        if result.reason == "EXACT_SYN_PACKET_PARTITION":
            tags = (*tags, "RECOVERED_" + str(result.label))
        elif result.status == "VERIFIED_MATCH":
            tags = (*tags, "BASELINE_" + str(result.label))
        for tag in tags:
            if tag not in examples:
                examples[tag] = {
                    "flow_id": flow.flow_id,
                    "source_sha256": raw["sha256"],
                    "packet_indices": [r.index for r in refs[:16]],
                    "full_packet_count": len(refs),
                    "omitted_sample_packet_count": max(0, len(refs) - 16),
                    "recorded_status": result.status,
                    "label": result.label,
                    "cardinality": result.cardinality,
                    "proof_digest": result.proof_digest,
                    "independent_partition_reference": partition_reference(
                        refs,
                        tuple(
                            r
                            for rs in labels.rows.values()
                            for r in rs
                            if r.reference in result.references
                        ),
                    )
                    if result.reason == "EXACT_SYN_PACKET_PARTITION"
                    else {"status": "NOT_APPLICABLE_TO_BASELINE"},
                    "reference_wire_digest": digest([asdict(r) for r in refs]),
                    "sample": [
                        {
                            "offset_ns": r.timestamp_ns - refs[0].timestamp_ns,
                            "flags": r.flags,
                            "ip_length": r.ip_length,
                            "relative_sequence": None
                            if r.sequence is None
                            else (
                                r.sequence
                                - (
                                    next(
                                        q.sequence
                                        for q in refs
                                        if q.endpoints == r.endpoints
                                        and q.sequence is not None
                                    )
                                )
                            )
                            % 2**32,
                            "payload_bytes": r.payload_length,
                            "payload_sha256": r.payload_sha256,
                            "first_seen_direction": r.endpoints == refs[0].endpoints,
                        }
                        for r in refs[:16]
                    ],
                }
        strict[before["status"]] += 1
        counts[result.status] += 1
        taxonomy[(before["label"] or "UNKNOWN") + " / " + before["reason"]] += 1
        if result.status == "VERIFIED_MATCH":
            classes[result.label] += 1
            if label_refs.intersection(result.references):
                raise ValueError("CROSS_FLOW_LABEL_REFERENCE_REUSE")
            if seen_packet_refs.intersection(p.event_id for p in flow.packets):
                raise ValueError("CROSS_FLOW_PACKET_REUSE")
            label_refs.update(result.references)
            seen_packet_refs.update(p.event_id for p in flow.packets)
        vector = (
            network_features(
                flow.packets,
                source_origin="OFFLINE_PCAP",
                source_identity=raw["sha256"],
            )
            if result.status == "VERIFIED_MATCH"
            else None
        )
        records.append(
            {
                "flow_id": flow.flow_id,
                "baseline_status": before["status"],
                "result": asdict(result),
                "feature_digest": vector.feature_digest if vector else None,
                "source_digest": vector.source_digest if vector else None,
                "label_references": list(result.references),
                "admitted": False,
            }
        )

    for record in PcapReader(_chunks(root / raw["relative_path"])):
        try:
            packet = parse_packet(record, raw["sha256"])
        except ValueError:
            continue
        # Existing saved input is ordered; do not replace a parse/gap failure with success.
        for flow in flows.add(packet):
            consume(flow)
    for flow in flows.finish(complete=True):
        consume(flow)
    if dict(strict) != {k: v for k, v in baseline["binding_status"].items() if v}:
        raise ValueError("FLOW_POPULATION_MISMATCH")
    result = {
        "session": raw["capture_session"],
        "source_sha256": raw["sha256"],
        "label_sha256": label["sha256"],
        "baseline_counts": baseline["counts"],
        "zeek_distribution": labels.counts,
        "baseline_binding": baseline["binding_status"],
        "current_binding": {
            k: counts[k]
            for k in (
                "VERIFIED_MATCH",
                "CANDIDATE_MATCH",
                "AMBIGUOUS",
                "UNMATCHED",
                "EXCLUDED",
            )
        },
        "baseline_verified_classes": baseline["verified_class_distribution"],
        "verified_classes": dict(classes),
        "new_verified": sum(
            r["baseline_status"] != "VERIFIED_MATCH"
            and r["result"]["status"] == "VERIFIED_MATCH"
            for r in records
        ),
        "failure_taxonomy_by_original_label": dict(taxonomy),
        "independent_reference_counts": reference_counts,
        "observed_packet_categories": dict(category_counts),
        "representative_references": examples,
        "diagnostic_rows_digest": digest(records),
        "verified_label_reference_count": len(label_refs),
        "admitted_samples": 0,
        "capture_quality": "UNKNOWN",
        "uid_reconstructed_from_pcap": False,
    }
    result["manifest_digest"] = digest(result)
    return result


def verify_policy_lock(document: dict[str, object]) -> None:
    repo = Path(__file__).resolve().parents[3]
    expected = {
        name: hashlib.sha256((repo / name).read_bytes()).hexdigest()
        for name in (
            "src/ml/iot23/recovery.py",
            "src/ml/iot23/wire_reference.py",
            "src/ml/iot23/binding_audit.py",
        )
    }
    if (
        document.get("policy_digest") != digest(policy())
        or document.get("source_sha256") != expected
        or document.get("test_opened_for_rule_selection") is not False
    ):
        raise ValueError("SEALED_TEST_REQUIRES_FROZEN_POLICY_SOURCE")
    if document.get("manifest_digest") != digest(
        {k: v for k, v in document.items() if k != "manifest_digest"}
    ):
        raise ValueError("POLICY_LOCK_TAMPERED")


def review_holdout(sessions: list[dict[str, object]]) -> dict[str, object]:
    if [r["session"] for r in sessions] != [
        "CTU-IoT-Malware-Capture-8-1",
        "CTU-IoT-Malware-Capture-20-1",
    ]:
        raise ValueError("TRAIN_VALIDATION_SESSION_BINDING_OR_TEST_LEAKAGE")
    presence = {
        name: "PASS"
        if all(
            report["verified_classes"].get(c, 0) > 0 for c in ("Benign", "Malicious")
        )
        else "BLOCKED"
        for name, report in zip(("train", "validation"), sessions, strict=True)
    }
    return {
        "class_presence": presence,
        "validation_malicious_flows": sessions[1]["verified_classes"].get(
            "Malicious", 0
        ),
        "independence": "UNVERIFIED_DEVICE_CAMPAIGN_GROUPS",
        "capture_quality": "UNKNOWN",
        "test_session": "34-1_SEALED",
        "random_row_split": False,
        "test_used_for_selection": False,
        "admission": "BLOCKED",
        "admitted_samples": 0,
        "reason": "Class presence alone does not prove independent holdout or capture quality",
    }


def audit(
    root: Path, *, sealed_test: bool = False, lock: dict[str, object] | None = None
) -> dict[str, object]:
    if sealed_test:
        verify_policy_lock(lock or {})
    repo = Path(__file__).resolve().parents[3]
    acquired = json.loads((root / "acquisition.json").read_text())
    verify_acquisition(
        acquired,
        json.loads((repo / "docs/network-training-download-plan.json").read_text()),
    )
    baseline = json.loads(
        (repo / "docs/iot23-network-admission-evidence.json").read_text()
    )["inspection"]
    sessions = ("34-1",) if sealed_test else ("8-1", "20-1")
    reports = []
    for sid in sessions:
        name = "CTU-IoT-Malware-Capture-" + sid
        files = [f for f in acquired["files"] if f["capture_session"] == name]
        report = audit_session(
            root,
            next(f for f in files if f["role"] == "PCAP"),
            next(f for f in files if f["role"] != "PCAP"),
            next(s for s in baseline["sessions"] if s["session"] == name),
        )
        reports.append(report)
    result = {
        "contract": "iot23-binding-recovery-audit:v1",
        "policy": policy(),
        "policy_digest": digest(policy()),
        "producer_configuration_digest": digest(producer_contract()),
        "sessions": reports,
        "scope": "SEALED_TEST_REGRESSION_ONLY"
        if sealed_test
        else "TRAIN_VALIDATION_DIAGNOSTIC",
        "test_used_for_rule_selection": False,
        "admitted_samples": 0,
        "admission": "BLOCKED",
        "operational_input": "NOT_INFERABLE",
        "write_disposition": "WRITE_DENIED",
    }
    if not sealed_test:
        result["holdout_review"] = review_holdout(reports)
    else:
        result["policy_lock_digest"] = lock["manifest_digest"]
    result["manifest_digest"] = digest(result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sealed-test", action="store_true")
    parser.add_argument("--policy-lock", type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError("AUDIT_OUTPUT_EXISTS")
    document = audit(
        args.root,
        sealed_test=args.sealed_test,
        lock=json.loads(args.policy_lock.read_text()) if args.policy_lock else None,
    )
    with args.output.open("x") as stream:
        json.dump(document, stream, indent=2)
        stream.write("\n")
    print(document["manifest_digest"])
