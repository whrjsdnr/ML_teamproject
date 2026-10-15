"""Read-only binding review; no declaration or saved candidate grants admission."""

import math
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from ml.ctu13.flows import Flow
from ml.ctu13.labels import LabelIndex, bind, flow_key
from ml.raw_acquisition.storage import FileReceipt
from ml.verified_producers.contracts import FeatureVector, digest
from ml.verified_producers.network_v1_1 import (
    feature_contract,
    network_features,
    producer_contract,
)

BindingStatus = Literal[
    "VERIFIED_MATCH", "CANDIDATE_MATCH", "AMBIGUOUS", "UNMATCHED", "EXCLUDED"
]


@dataclass(frozen=True)
class BindingReview:
    status: BindingStatus
    reason: str
    label_reference: str | None = None


def review_binding(
    flow: Flow, labels: LabelIndex, *, source_origin: str, source_identity: str
) -> BindingReview:
    if flow.incomplete:
        return BindingReview("EXCLUDED", flow.reason or flow.closure)
    try:
        network_features(
            flow.packets, source_origin=source_origin, source_identity=source_identity
        )
    except (ValueError, TypeError, OverflowError):
        return BindingReview("EXCLUDED", "INVALID_FLOW_OR_SOURCE")
    key = flow_key(flow.packets[0])
    if any(flow_key(p) != key for p in flow.packets):
        return BindingReview("EXCLUDED", "MIXED_FLOW")
    if source_origin == "OFFLINE_PCAP" and any(
        p.capture_session_id != source_identity for p in flow.packets
    ):
        return BindingReview("EXCLUDED", "OFFLINE_SOURCE_IDENTITY_MISMATCH")
    if any(
        l.key != key or not re.fullmatch(r"[a-f0-9]{64}", l.reference)
        for l in labels.rows.get(key, ())
    ):
        return BindingReview("EXCLUDED", "FORGED_LABEL_BINDING")
    # Existing matcher is reused. A caller's clock_verified flag is insufficient
    # evidence of the actual CTU label-export TZ/command, so do not trust it here.
    status, label = bind(flow.packets, replace(labels, clock_verified=False))
    if status == "AMBIGUOUS":
        return BindingReview("AMBIGUOUS", "DUPLICATE_OR_CONFLICTING_INTERVAL")
    if status == "UNMATCHED":
        return BindingReview("UNMATCHED", "NO_EXACT_SESSION_TUPLE_INTERVAL")
    if status != "CLOCK_UNVERIFIED" or label is None:
        return BindingReview("EXCLUDED", status)
    if label.direction.strip() not in {"->", "<-", "<->", "<?>", "?>", "<?"}:
        return BindingReview("EXCLUDED", "UNSUPPORTED_LABEL_DIRECTION")
    return BindingReview(
        "CANDIDATE_MATCH",
        "TIMEZONE_UNVERIFIED; first-observed direction is not Argus initiator",
        label.reference,
    )


def inspect_saved(root: Path, evidence_path: Path) -> dict[str, object]:
    """Recheck immutable compressed originals and saved vectors without decompression.

    No raw flow endpoints were saved with these privacy-minimized rows, so source
    binding cannot be independently replayed. VERIFIED_MATCH is intentionally zero.
    """
    import hashlib
    import json

    from ml.ctu13.labels import load_labels

    evidence = json.loads(evidence_path.read_text())
    expected = evidence.pop("evidence_summary_digest")
    if digest(evidence) != expected:
        raise ValueError("SAVED_EVIDENCE_DIGEST_MISMATCH")
    receipts = []
    for item in evidence["source_files"]:
        filename = item["filename"]
        if filename not in {
            "capture20110816-2.truncated.pcap.bz2",
            "capture20110816-2.binetflow",
        }:
            raise ValueError("UNEXPECTED_SOURCE")
        path = root / filename
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size != item["size_bytes"]
        ):
            raise ValueError("RAW_FILE_IDENTITY_MISMATCH")
        with path.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != item["sha256"]:
            raise ValueError("RAW_DIGEST_MISMATCH")
        receipts.append(
            FileReceipt(
                filename, item["size_bytes"], actual, item["content_type"], False
            )
        )
    source = evidence["source_files"][0]["sha256"]
    label_identity = evidence["source_files"][1]["sha256"]
    labels = load_labels(
        root / "capture20110816-2.binetflow",
        label_identity=label_identity,
        session_identity=source,
        utc_offset_seconds=7200,
        clock_verified=False,
    )
    refs = {label.reference: label for group in labels.rows.values() for label in group}
    path = root / "pilot-candidates.jsonl"
    if path.is_symlink() or path.stat().st_size > 8 * 1024**2:
        raise ValueError("SAVED_ROWS_INVALID")
    content = path.read_bytes()
    if hashlib.sha256(content).hexdigest() != evidence["dataset_digest"]:
        raise ValueError("SAVED_DATASET_TAMPERED")
    seen = set()
    rows = 0
    classes = {}
    for line in content.splitlines():
        row = json.loads(line)
        vector = FeatureVector(**row["vector"])
        if (
            row["flow_digest"] in seen
            or row["training_admitted"] is not False
            or row["binding_status"] != "CLOCK_UNVERIFIED"
            or row["split_group"] != source
            or row["label_reference"] not in refs
            or row["label"] != refs[row["label_reference"]].classification
            or vector.semantic_version != "1.1.0"
            or vector.source_origin != "OFFLINE_PCAP"
            or vector.configuration_digest != digest(producer_contract())
            or tuple(vector.feature_names) != tuple(feature_contract()["names"])
            or len(vector.values) != 14
            or not all(math.isfinite(n) for n in vector.values)
            or vector.feature_digest != row["feature_digest"]
        ):
            raise ValueError("SAVED_BINDING_OR_VECTOR_INVALID")
        seen.add(row["flow_digest"])
        rows += 1
        classes[row["label"]] = classes.get(row["label"], 0) + 1
    return {
        "source_origin": "OFFLINE_PCAP",
        "new_decompressed_bytes": 0,
        "source_file_hashes_verified": len(receipts),
        "saved_rows_verified": rows,
        "candidate_matches": rows,
        "verified_matches": 0,
        "admitted_samples": 0,
        "candidate_label_distribution": classes,
        "label_rows_rechecked": labels.counts,
        "raw_flow_binding": "NOT_REPLAYED_NO_PACKET_ENDPOINT_SNAPSHOT",
        "full_stream_verified": False,
        "timezone": "TIMEZONE_UNVERIFIED",
        "direction": "FIRST_OBSERVED_NOT_ARGUS_INITIATOR",
        "admission": "BLOCKED",
        "blockers": [
            "FULL_STREAM_NOT_VERIFIED",
            "TIMEZONE_UNVERIFIED",
            "BINDING_ONLY_SAVED_CANDIDATE",
            "CAPTURE_QUALITY_UNKNOWN",
            "SINGLE_SESSION_NO_INDEPENDENT_HOLDOUT",
        ],
        "producer_config_digest": digest(producer_contract()),
        "feature_contract_digest": digest(feature_contract()),
        "inference": "NOT_INFERABLE",
        "finding_promotion": "BLOCKED",
        "write": "WRITE_DENIED",
    }
