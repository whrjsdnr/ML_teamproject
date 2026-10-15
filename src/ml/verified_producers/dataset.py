"""Fail-closed admission checks, not a trainer or provenance attestation service."""

import re
from dataclasses import asdict, dataclass

from ml.verified_producers.contracts import contract, digest


@dataclass(frozen=True)
class Sample:
    sample_id: str
    raw_digest: str
    label: int
    label_reference: str
    label_origin: str
    source_group: str
    split: str
    raw_kind: str
    source_origin: str


def dataset_manifest(
    dataset_id: str, version: str, kind: str, samples: tuple[Sample, ...]
) -> dict[str, object]:
    """Validate declarations only. Raw bytes and label authority require separate verification.

    source_group must cover capture session/incident for Network, and an independently
    assigned domain/source family for DNS (not a guessed public suffix). This helper
    cannot discover dishonest group assignments or establish a time-disjoint holdout.
    """
    configuration = contract(kind)
    if not dataset_id or not version or not samples:
        raise ValueError("DATASET_MISSING")
    if len({s.sample_id for s in samples}) != len(samples):
        raise ValueError("DUPLICATE_SAMPLE")
    if len({s.raw_digest for s in samples}) != len(samples):
        raise ValueError("DUPLICATE_RAW_INPUT")
    groups: dict[str, str] = {}
    counts = {
        split: {"positive": 0, "negative": 0}
        for split in ("train", "validation", "test")
    }
    expected_kind = "PACKET_METADATA" if kind == "network" else "RAW_FQDN"
    for sample in samples:
        if (
            not sample.sample_id
            or not sample.source_group
            or not re.fullmatch(r"[0-9a-f]{64}", sample.raw_digest)
        ):
            raise ValueError("INVALID_SOURCE_BINDING")
        if sample.source_origin != "RAW_DATASET" or sample.raw_kind != expected_kind:
            raise ValueError("RAW_LABELED_DATA_REQUIRED")
        if (
            sample.label_origin != "INDEPENDENT_DATASET_LABEL"
            or not sample.label_reference
            or type(sample.label) is not int
            or sample.label not in (0, 1)
        ):
            raise ValueError("INDEPENDENT_LABEL_REQUIRED")
        if sample.split not in counts:
            raise ValueError("UNKNOWN_SPLIT")
        if (
            sample.source_group in groups
            and groups[sample.source_group] != sample.split
        ):
            raise ValueError("GROUP_SPLIT_LEAKAGE")
        groups[sample.source_group] = sample.split
        counts[sample.split]["positive" if sample.label else "negative"] += 1
    if any(not c["positive"] or not c["negative"] for c in counts.values()):
        raise ValueError("BOTH_CLASSES_REQUIRED_IN_EACH_SPLIT")
    ordered = [asdict(s) for s in sorted(samples, key=lambda s: s.sample_id)]
    return {
        "dataset_id": dataset_id,
        "version": version,
        "configuration_digest": digest(configuration),
        "declared_samples_digest": digest(ordered),
        "label_digest": digest(
            [(s["sample_id"], s["label"], s["label_reference"]) for s in ordered]
        ),
        "split_counts": counts,
        "dataset_size": len(samples),
        "validation_status": "DECLARATIONS_ONLY_NOT_TRAINING_AUTHORITY",
        "raw_bytes_verified": False,
        "label_authority_verified": False,
        "temporal_holdout_verified": False,
        "operational_promotion": "BLOCKED",
    }
