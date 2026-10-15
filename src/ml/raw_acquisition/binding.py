"""Pure binding/leakage checks; labels must come from reviewed external files."""

import re
from dataclasses import asdict, dataclass
from typing import Literal

from ml.verified_producers.contracts import contract, digest
from ml.verified_producers.dns import dns_features
from ml.verified_producers.network import Packet, network_features


@dataclass(frozen=True)
class NetworkLabel:
    session: str
    source_address: str
    destination_address: str
    source_port: int
    destination_port: int
    transport: str
    start_ns: int
    end_ns: int
    label: Literal[0, 1] | None
    reference: str


def bind_network(
    packets: tuple[Packet, ...], labels: tuple[NetworkLabel, ...], *, source_origin: str
) -> str:
    network_features(packets, source_origin=source_origin, capture_quality="UNKNOWN")
    first = packets[0]
    matches = []
    for label in labels:
        if (
            type(label.start_ns) is not int
            or type(label.end_ns) is not int
            or label.start_ns > label.end_ns
        ):
            raise ValueError("INVALID_LABEL_INTERVAL")
        endpoints = (
            (label.source_address, label.source_port),
            (label.destination_address, label.destination_port),
        )
        if (
            label.session == first.capture_session_id
            and label.transport == first.transport
            and first.endpoints in (endpoints, tuple(reversed(endpoints)))
            and label.start_ns
            <= first.timestamp_ns
            <= packets[-1].timestamp_ns
            <= label.end_ns
        ):
            matches.append(label)
    if not matches:
        raise ValueError("UNMATCHED_LABEL_EXCLUDED")
    if len(matches) != 1:
        raise ValueError("AMBIGUOUS_LABEL_EXCLUDED")
    match = matches[0]
    if type(match.label) is not int or match.label not in (0, 1) or not match.reference:
        raise ValueError("UNKNOWN_LABEL_EXCLUDED")
    # Return the external row reference, never generate the answer from features.
    return match.reference


@dataclass(frozen=True)
class DomainLabel:
    fqdn: str
    label: Literal[0, 1] | None
    reference: str
    source: str


def canonical_domain(value: str) -> str:
    dns_features(value, source_origin="RAW_LABELED_FQDN")
    return value.removesuffix(".").lower()


def bind_dns(fqdn: str, labels: tuple[DomainLabel, ...]) -> str:
    name = canonical_domain(fqdn)
    matches = [label for label in labels if canonical_domain(label.fqdn) == name]
    if not matches:
        raise ValueError("UNMATCHED_LABEL_EXCLUDED")
    if len(matches) != 1:
        raise ValueError("DUPLICATE_OR_CONFLICTING_DOMAIN_EXCLUDED")
    match = matches[0]
    if (
        type(match.label) is not int
        or match.label not in (0, 1)
        or not match.reference
        or not match.source
    ):
        raise ValueError("UNKNOWN_LABEL_EXCLUDED")
    return match.reference


@dataclass(frozen=True)
class SplitRecord:
    sample_digest: str
    feature_digest: str
    label_reference: str
    label: Literal[0, 1]
    split: Literal["train", "validation", "test"]
    groups: tuple[str, ...]
    start_ns: int
    end_ns: int


def validate_split(records: tuple[SplitRecord, ...]) -> str:
    """Input groups must include independently reviewed session/host or registered-domain/campaign.

    This rejects declared overlap, but cannot discover dishonest grouping, prove label
    authority, or substitute for a pinned public-suffix/campaign mapping.
    """
    if not records:
        raise ValueError("EMPTY_DATASET")
    groups = {}
    samples = set()
    features = set()
    counts = {s: {0: 0, 1: 0} for s in ("train", "validation", "test")}
    intervals = {s: [] for s in counts}
    for record in records:
        if (
            record.split not in counts
            or not record.label_reference
            or type(record.label) is not int
            or record.label not in (0, 1)
        ):
            raise ValueError("INVALID_SPLIT_LABEL")
        if (
            not record.groups
            or any(not g for g in record.groups)
            or type(record.start_ns) is not int
            or type(record.end_ns) is not int
            or not 0 <= record.start_ns <= record.end_ns
        ):
            raise ValueError("INDEPENDENCE_METADATA_MISSING")
        if not all(
            re.fullmatch(r"[0-9a-f]{64}", h)
            for h in (record.sample_digest, record.feature_digest)
        ):
            raise ValueError("INVALID_SAMPLE_DIGEST")
        if record.sample_digest in samples or record.feature_digest in features:
            raise ValueError("DUPLICATE_SAMPLE_OR_FEATURE")
        samples.add(record.sample_digest)
        features.add(record.feature_digest)
        for group in record.groups:
            if group in groups and groups[group] != record.split:
                raise ValueError("GROUP_LEAKAGE")
            groups[group] = record.split
        intervals[record.split].append((record.start_ns, record.end_ns))
        counts[record.split][record.label] += 1
    if any(not value[0] or not value[1] for value in counts.values()):
        raise ValueError("INDEPENDENT_CLASS_SPLITS_MISSING")
    # Strict chronology: a collection period cannot span an adjacent split boundary.
    for left, right in (("train", "validation"), ("validation", "test")):
        if max(end for _, end in intervals[left]) >= min(
            start for start, _ in intervals[right]
        ):
            raise ValueError("TEMPORAL_SPLIT_LEAKAGE")
    ordered = sorted((asdict(r) for r in records), key=lambda r: r["sample_digest"])
    return digest({"records": ordered, "rule": "explicit-groups-strict-time:v1"})


def feature_contract_digest(kind: str) -> str:
    config = contract(kind)
    return digest(
        {
            "producer_id": config["producer_id"],
            "semantic_version": config["semantic_version"],
            "feature_names": config["feature_names"],
            "dtype": config["dtype"],
        }
    )
