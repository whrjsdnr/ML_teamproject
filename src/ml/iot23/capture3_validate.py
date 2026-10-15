"""Offline Capture3 measurement with frozen binding/producer and blocked admission."""

import argparse
import gc
import json
import math
import struct
from collections import Counter
from pathlib import Path

from ml.ctu13.flows import Flows
from ml.ctu13.pcap import PcapReader, parse_packet
from ml.iot23.binding_audit import audit, audit_session, verify_policy_lock
from ml.iot23.capture3_acquire import STORAGE, verify_receipt
from ml.iot23.inspect import (
    _chunks,
    file_sha256,
    inspect_session,
    reference_document,
    verify_reference,
)
from ml.iot23.integrity import GATES, admission
from ml.iot23.recovery import policy, recover
from ml.iot23.wire_reference import read_reference
from ml.iot23.zeek import load
from ml.verified_producers.contracts import NETWORK_NAMES, digest
from ml.verified_producers.network_v1_1 import (
    feature_contract,
    network_features,
    producer_contract,
)


def trace_details(
    root: Path,
    raw: dict[str, object],
    label: dict[str, object],
    before: dict[str, tuple[str, str | None]],
) -> dict[str, object]:
    """Observe existing decisions; never implement another binding decision engine."""
    wires, _ = read_reference(root / raw["relative_path"], raw["sha256"])
    labels = load(root / label["relative_path"], label["sha256"], raw["sha256"])
    flows = Flows()
    counts = Counter()
    reasons = Counter()
    cardinality = Counter()
    references = {}
    vectors = 0

    def consume(flow):
        nonlocal vectors
        prior_status, prior_label = before[flow.flow_id]
        result = recover(flow, labels, wires)
        status, classification = result.status, result.label
        # Match the unchanged audit_session post-baseline exclusions exactly.
        if (
            prior_status != "VERIFIED_MATCH"
            and result.reason != "EXACT_SYN_PACKET_PARTITION"
        ):
            status, classification = prior_status, prior_label
        counts[status + " / " + (classification or "UNKNOWN")] += 1
        reasons[
            status + " / " + (classification or "UNKNOWN") + " / " + result.reason
        ] += 1
        cardinality[result.cardinality] += 1
        if status == "VERIFIED_MATCH":
            vector = network_features(
                flow.packets,
                source_origin="OFFLINE_PCAP",
                source_identity=raw["sha256"],
            )
            if (
                vector.feature_names != NETWORK_NAMES
                or len(vector.values) != 14
                or not all(
                    math.isfinite(v)
                    and struct.unpack("!f", struct.pack("!f", v))[0] == v
                    for v in vector.values
                )
            ):
                raise ValueError("FEATURE14_CONTRACT_FAILURE")
            vectors += 1
            if classification not in references and len(flow.packets) >= 2:
                document = reference_document(flow.packets, raw["sha256"])
                verify_reference(flow.packets, document, raw["sha256"])
                references[classification] = document

    for record in PcapReader(_chunks(root / raw["relative_path"])):
        try:
            packet = parse_packet(record, raw["sha256"])
        except ValueError:
            continue
        for flow in flows.add(packet):
            consume(flow)
    for flow in flows.finish(complete=True):
        consume(flow)
    return {
        "status_by_source_label": dict(counts),
        "reason_by_source_label": dict(reasons),
        "mapping_cardinality": dict(cardinality),
        "finite_float32_vectors": vectors,
        "actual_capture3_reference_pairs": references,
        "feature_schema_digest": digest(feature_contract()),
        "producer_config_digest": digest(producer_contract()),
        "operational_parity": "NOT_VERIFIED",
    }


def holdout_review(
    train: dict[str, object],
    candidate: dict[str, object],
    *,
    train_range: list[int],
    candidate_range: list[int],
    origin_overlap: int,
    exact_duplicates: int,
) -> dict[str, object]:
    if (
        train["session"] != "CTU-IoT-Malware-Capture-8-1"
        or candidate["session"] != "CTU-IoT-Malware-Capture-3-1"
    ):
        raise ValueError("TEST_OR_DIAGNOSTIC_SESSION_CANNOT_REPLACE_FIXED_SPLIT")
    class_presence = {
        name: "PASS"
        if all(row["verified_classes"].get(c, 0) > 0 for c in ("Benign", "Malicious"))
        else "BLOCKED"
        for name, row in [("train", train), ("validation_candidate", candidate)]
    }
    temporal_overlap = not (
        train_range[1] < candidate_range[0] or candidate_range[1] < train_range[0]
    )
    forward_order = train_range[1] < candidate_range[0]
    gates = dict.fromkeys(GATES, "PASS")
    gates.update(
        split_leakage="UNVERIFIED_DEVICE_CAMPAIGN",
        holdout="BLOCKED"
        if temporal_overlap or not forward_order or "BLOCKED" in class_presence.values()
        else "UNVERIFIED",
        capture_quality="UNKNOWN",
    )
    decision = admission(gates)
    return {
        "fixed_roles": {
            "train": "8-1",
            "validation_candidate": "3-1",
            "diagnostic": "20-1",
            "test": "34-1_SEALED",
        },
        "class_presence": class_presence,
        "time_overlap": "FAIL" if temporal_overlap else "PASS_NO_OVERLAP",
        "forward_chronology": "PASS"
        if forward_order
        else "FAIL_VALIDATION_PREDATES_TRAIN",
        "origin_address_hash_overlap": origin_overlap,
        "exact_raw_flow_duplicate_count": exact_duplicates,
        "device_independence": "UNVERIFIED",
        "campaign_independence": "UNVERIFIED_DIFFERENT_FAMILY_IS_NOT_SUFFICIENT",
        "capture_quality": "UNKNOWN",
        "source_group_leakage": "UNVERIFIED",
        "test34_reassigned": False,
        "model_selection_executed": False,
        "gates": gates,
        "independent_validation": "BLOCKED",
        "admission": decision,
        "network_quality": decision,
        "network_edge": decision,
        "admitted_samples": 0,
    }


def validate(
    repo: Path, *, raw_root: Path | None = None, prior_root: Path | None = None
) -> dict[str, object]:
    root = raw_root if raw_root is not None else repo / STORAGE
    plan = json.loads((repo / "docs/iot23-capture3-download-plan.json").read_text())
    receipt = json.loads((root / "acquisition.json").read_text())
    verify_receipt(receipt, plan)
    lock = json.loads(
        (repo / "docs/iot23-binding-recovery-policy-lock.json").read_text()
    )
    verify_policy_lock(lock)
    raw, label = receipt["files"]
    baseline, rows = inspect_session(root, raw, label)
    before = {r["flow_id"]: (r["status"], r["label"]) for r in rows}
    fingerprints = {r["raw_fingerprint"] for r in rows}
    del rows
    gc.collect()
    recovered = audit_session(root, raw, label, baseline)
    gc.collect()
    details = trace_details(root, raw, label, before)
    if (
        details["finite_float32_vectors"]
        != recovered["current_binding"]["VERIFIED_MATCH"]
    ):
        raise ValueError("TRACE_AUDIT_DISAGREEMENT")
    for status, expected in recovered["current_binding"].items():
        if (
            sum(
                n
                for key, n in details["status_by_source_label"].items()
                if key.startswith(status + " / ")
            )
            != expected
        ):
            raise ValueError("TRACE_POPULATION_MISMATCH")
    prior_root = (
        prior_root
        if prior_root is not None
        else repo / "data/raw/acquisition/iot23-network14-3sessions-v1"
    )
    prior_acquired = json.loads((prior_root / "acquisition.json").read_text())
    for row in prior_acquired["files"]:
        if file_sha256(prior_root / row["relative_path"]) != row["sha256"]:
            raise ValueError("EXISTING_RAW_DATA_CHANGED")
    prior_audit = audit(
        prior_root
    )  # Fresh train8 + diagnostic20 only; no sealed34 parsing.
    old_expected = json.loads(
        (repo / "docs/iot23-binding-recovery-evidence.json").read_text()
    )["train_validation"]
    if prior_audit != old_expected:
        raise ValueError("FROZEN_PRIOR_AUDIT_REGRESSION")
    train_raw = next(
        r
        for r in prior_acquired["files"]
        if r["role"] == "PCAP" and r["capture_session"].endswith("-8-1")
    )
    train_label = next(
        r
        for r in prior_acquired["files"]
        if r["role"] != "PCAP" and r["capture_session"] == train_raw["capture_session"]
    )
    train_base, train_rows = inspect_session(prior_root, train_raw, train_label)
    duplicates = len(fingerprints & {r["raw_fingerprint"] for r in train_rows})
    overlap = len(
        set(baseline["observed_origin_address_hashes"])
        & set(train_base["observed_origin_address_hashes"])
    )
    review = holdout_review(
        prior_audit["sessions"][0],
        recovered,
        train_range=train_base["time_range_ns"],
        candidate_range=baseline["time_range_ns"],
        origin_overlap=overlap,
        exact_duplicates=duplicates,
    )
    result = {
        "contract": "iot23-capture3-validation:v1",
        "download": receipt,
        "baseline": baseline,
        "binding": recovered,
        "details": details,
        "holdout": review,
        "reused_policy_digest": digest(policy()),
        "policy_lock_digest": lock["manifest_digest"],
        "frozen_train_diagnostic_audit_digest": prior_audit["manifest_digest"],
        "admission": "BLOCKED",
        "admitted_samples": 0,
        "training_executed": False,
        "operational_input": "NOT_INFERABLE",
        "write_disposition": "WRITE_DENIED",
    }
    result["manifest_digest"] = digest(result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--raw-root", type=Path)
    parser.add_argument("--prior-root", type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError("VALIDATION_OUTPUT_EXISTS")
    document = validate(
        Path(__file__).resolve().parents[3],
        raw_root=args.raw_root,
        prior_root=args.prior_root,
    )
    with args.output.open("x") as stream:
        json.dump(document, stream, indent=2)
        stream.write("\n")
    print(document["manifest_digest"])
