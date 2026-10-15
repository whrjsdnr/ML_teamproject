"""Network14 v1.1: explicit offline origin, without legacy model authority.

Arithmetic is version-isolated from v1.0; regression compares both on fixtures.
Source declarations bind digests but are not capture attestations.
"""

import math
import re
import struct
from dataclasses import asdict
from itertools import pairwise

from ml.verified_producers.contracts import (
    NETWORK_NAMES,
    FeatureVector,
    contract,
    digest,
)
from ml.verified_producers.network import Packet


def feature_contract() -> dict[str, object]:
    return {
        "version": "1.0.0",
        "names": NETWORK_NAMES,
        "dtype": "float32",
        "scaling": "NONE",
    }


def producer_contract() -> dict[str, object]:
    config = contract("network")
    config.update(
        semantic_version="1.1.0",
        feature_contract_digest=digest(feature_contract()),
        source_origins=["OFFLINE_PCAP", "NATIVE_AF_PACKET", "FIXTURE"],
        timestamp_policy="PCAP recorded epoch with declared resolution; native kernel timestamp; fixture explicit",
        truncation_policy="payload truncation allowed only when all required IP/transport metadata are present",
        loss_policy="UNKNOWN diagnostic only; KNOWN_GAP rejected",
        authority="NO_OPERATIONAL_INFERENCE_OR_PROMOTION",
    )
    return config


def network_features(
    packets: tuple[Packet, ...],
    *,
    source_origin: str,
    source_identity: str,
    capture_quality: str = "UNKNOWN",
) -> FeatureVector:
    if source_origin not in {"OFFLINE_PCAP", "NATIVE_AF_PACKET", "FIXTURE"}:
        raise ValueError("UNKNOWN_SOURCE_ORIGIN")
    if not re.fullmatch("[a-f0-9]{64}", source_identity):
        raise ValueError("INVALID_SOURCE_IDENTITY")
    if capture_quality not in {"UNKNOWN", "CONFIRMED_NO_DROPS_IN_WINDOW"}:
        raise ValueError("INCOMPLETE_CAPTURE")
    if not isinstance(packets, tuple) or not 1 <= len(packets) <= 4096:
        raise ValueError("PACKET_LIMIT")
    if not all(isinstance(p, Packet) for p in packets):
        raise ValueError("INVALID_PACKET_SCHEMA")
    if len({p.event_id for p in packets}) != len(packets):
        raise ValueError("DUPLICATE_EVENT")
    first = packets[0]
    if any(
        p.interface_id != first.interface_id
        or p.capture_session_id != first.capture_session_id
        or p.transport != first.transport
        or p.endpoints not in (first.endpoints, first.endpoints[::-1])
        for p in packets
    ):
        raise ValueError("MIXED_FLOW")
    deltas = tuple(b.timestamp_ns - a.timestamp_ns for a, b in pairwise(packets))
    duration = packets[-1].timestamp_ns - first.timestamp_ns
    if duration >= 120_000_000_000 or any(d < 0 or d >= 30_000_000_000 for d in deltas):
        raise ValueError("ORDER_OR_TIMEOUT_BOUNDARY")
    forward = [p for p in packets if p.endpoints == first.endpoints]
    backward = [p for p in packets if p.endpoints != first.endpoints]
    lengths = [p.ip_length for p in packets]
    mean = math.fsum(lengths) / len(lengths)
    values = (
        duration / 1e9,
        len(forward),
        len(backward),
        sum(p.ip_length for p in forward),
        sum(p.ip_length for p in backward),
        min(lengths),
        max(lengths),
        mean,
        math.sqrt(math.fsum((n - mean) ** 2 for n in lengths) / len(lengths)),
        sum(bool(p.tcp_flags & 2) for p in packets),
        sum(bool(p.tcp_flags & 1) for p in packets),
        sum(bool(p.tcp_flags & 4) for p in packets),
        math.fsum(deltas) / len(deltas) / 1e9 if deltas else 0.0,
        max(deltas) / 1e9 if deltas else 0.0,
    )
    converted = tuple(struct.unpack("!f", struct.pack("!f", n))[0] for n in values)
    if not all(math.isfinite(n) for n in converted):
        raise ValueError("NONFINITE_FEATURE")
    return FeatureVector(
        "linux-observable-network",
        "1.1.0",
        digest(producer_contract()),
        digest(
            {
                "packets": [asdict(p) for p in packets],
                "source_identity": source_identity,
                "origin": source_origin,
                "quality": capture_quality,
            }
        ),
        NETWORK_NAMES,
        converted,
        source_origin,
        capture_quality,
    )


def verify_reference(
    packets: tuple[Packet, ...],
    reference: dict[str, object],
    *,
    source_identity: str,
    source_origin: str,
) -> None:
    result = network_features(
        packets, source_origin=source_origin, source_identity=source_identity
    )
    expected = {
        "producer_version": "1.1.0",
        "configuration_digest": digest(producer_contract()),
        "feature_contract_digest": digest(feature_contract()),
        "source_identity": source_identity,
        "source_origin": source_origin,
        "source_digest": result.source_digest,
        "feature_names": list(result.feature_names),
        "values": list(result.values),
    }
    if any(reference.get(k) != v for k, v in expected.items()):
        raise ValueError("REFERENCE_MISMATCH")
