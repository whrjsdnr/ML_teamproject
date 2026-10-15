"""Metadata-only experimental flow arithmetic; no capture or flow reassembly."""

import ipaddress
import math
import re
from dataclasses import asdict, dataclass
from itertools import pairwise

from ml.verified_producers.contracts import FeatureVector, vector


@dataclass(frozen=True)
class Packet:
    event_id: str
    interface_id: str
    capture_session_id: str
    timestamp_ns: int
    source_address: str
    destination_address: str
    source_port: int
    destination_port: int
    transport: str
    ip_length: int
    tcp_flags: int = 0

    def __post_init__(self) -> None:
        for value, minimum, maximum in (
            (self.timestamp_ns, 0, 2**63 - 1),
            (self.source_port, 0, 65535),
            (self.destination_port, 0, 65535),
            (self.ip_length, 20, 65535),
            (self.tcp_flags, 0, 511),
        ):
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError("INVALID_PACKET_NUMBER")
        if not isinstance(self.event_id, str) or not 1 <= len(self.event_id) <= 256:
            raise ValueError("INVALID_EVENT_ID")
        if not isinstance(self.interface_id, str) or not re.fullmatch(
            r"[0-9a-f]{64}", self.interface_id
        ):
            raise ValueError("INVALID_INTERFACE_ID")
        if (
            not isinstance(self.capture_session_id, str)
            or not 1 <= len(self.capture_session_id) <= 128
        ):
            raise ValueError("INVALID_CAPTURE_SESSION")
        src = ipaddress.ip_address(self.source_address)
        dst = ipaddress.ip_address(self.destination_address)
        if str(src) != self.source_address or str(dst) != self.destination_address:
            raise ValueError("NON_CANONICAL_ADDRESS")
        if src.version != dst.version or (src.version == 6 and self.ip_length < 40):
            raise ValueError("INVALID_ADDRESS_FAMILY")
        if self.transport not in {"tcp", "udp"} or (
            self.transport == "udp" and self.tcp_flags
        ):
            raise ValueError("INVALID_TRANSPORT")
        minimum_length = (20 if src.version == 4 else 40) + (
            20 if self.transport == "tcp" else 8
        )
        if self.ip_length < minimum_length:
            raise ValueError("TRUNCATED_TRANSPORT")
        if (self.source_address, self.source_port) == (
            self.destination_address,
            self.destination_port,
        ):
            raise ValueError("AMBIGUOUS_FLOW_DIRECTION")

    @property
    def endpoints(self) -> tuple[tuple[str, int], tuple[str, int]]:
        return (self.source_address, self.source_port), (
            self.destination_address,
            self.destination_port,
        )


def network_features(
    packets: tuple[Packet, ...], *, source_origin: str, capture_quality: str
) -> FeatureVector:
    if source_origin not in {"EXPLICIT_PACKET_FIXTURE", "NATIVE_AF_PACKET"}:
        raise ValueError("UNKNOWN_SOURCE_ORIGIN")
    if capture_quality not in {"UNKNOWN", "CONFIRMED_NO_DROPS_IN_WINDOW"}:
        raise ValueError("INCOMPLETE_CAPTURE")
    if not isinstance(packets, tuple) or not 1 <= len(packets) <= 4096:
        raise ValueError("PACKET_LIMIT")
    if not all(isinstance(p, Packet) for p in packets):
        raise ValueError("INVALID_PACKET_SCHEMA")
    if len({p.event_id for p in packets}) != len(packets):
        raise ValueError("DUPLICATE_EVENT")
    first = packets[0]
    reverse = tuple(reversed(first.endpoints))
    if any(
        p.transport != first.transport
        or p.interface_id != first.interface_id
        or p.capture_session_id != first.capture_session_id
        or p.endpoints not in (first.endpoints, reverse)
        for p in packets
    ):
        raise ValueError("MIXED_FLOW")
    deltas = tuple(b.timestamp_ns - a.timestamp_ns for a, b in pairwise(packets))
    duration = packets[-1].timestamp_ns - first.timestamp_ns
    if any(d < 0 or d >= 30_000_000_000 for d in deltas) or duration >= 120_000_000_000:
        raise ValueError("ORDER_OR_TIMEOUT_BOUNDARY")
    forward = tuple(p for p in packets if p.endpoints == first.endpoints)
    backward = tuple(p for p in packets if p.endpoints != first.endpoints)
    lengths = tuple(p.ip_length for p in packets)
    mean = math.fsum(lengths) / len(lengths)
    std = math.sqrt(math.fsum((x - mean) ** 2 for x in lengths) / len(lengths))
    values = (
        duration / 1e9,
        len(forward),
        len(backward),
        sum(p.ip_length for p in forward),
        sum(p.ip_length for p in backward),
        min(lengths),
        max(lengths),
        mean,
        std,
        sum(bool(p.tcp_flags & 2) for p in packets),
        sum(bool(p.tcp_flags & 1) for p in packets),
        sum(bool(p.tcp_flags & 4) for p in packets),
        math.fsum(deltas) / len(deltas) / 1e9 if deltas else 0.0,
        max(deltas) / 1e9 if deltas else 0.0,
    )
    source = {
        "packets": [asdict(p) for p in packets],
        "source_origin": source_origin,
        "capture_quality": capture_quality,
    }
    return vector("network", source, values, source_origin, capture_quality)
