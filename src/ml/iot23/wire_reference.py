"""Independent classic-PCAP/header reference, without the production packet parser.

Bounded offline only. No socket, payload retention, feature production or execution.
"""

import hashlib
import ipaddress
import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WirePacket:
    index: int
    timestamp_ns: int
    endpoints: tuple[tuple[str, int], tuple[str, int]]
    transport: str
    ip_length: int
    flags: int
    sequence: int | None
    acknowledgment: int | None
    payload_length: int
    payload_sha256: str
    complete: bool


def decode_frame(
    index: int, timestamp_ns: int, frame: bytes, wire_length: int
) -> WirePacket:
    if len(frame) < 14:
        raise ValueError("REFERENCE_ETHERNET_TRUNCATED")
    offset = 14
    kind = struct.unpack_from("!H", frame, 12)[0]
    if kind in (0x8100, 0x88A8):
        if len(frame) < 18:
            raise ValueError("REFERENCE_VLAN_TRUNCATED")
        kind = struct.unpack_from("!H", frame, 16)[0]
        offset = 18
    if kind == 0x0800:
        if len(frame) < offset + 20 or frame[offset] >> 4 != 4:
            raise ValueError("REFERENCE_IPV4_INVALID")
        header_length = (frame[offset] & 15) * 4
        length = struct.unpack_from("!H", frame, offset + 2)[0]
        if (
            header_length < 20
            or len(frame) < offset + header_length
            or length < header_length
        ):
            raise ValueError("REFERENCE_IPV4_INVALID")
        if struct.unpack_from("!H", frame, offset + 6)[0] & 0x3FFF:
            raise ValueError("REFERENCE_FRAGMENT_UNSUPPORTED")
        proto = frame[offset + 9]
        src = str(ipaddress.IPv4Address(frame[offset + 12 : offset + 16]))
        dst = str(ipaddress.IPv4Address(frame[offset + 16 : offset + 20]))
    elif kind == 0x86DD:
        if len(frame) < offset + 40 or frame[offset] >> 4 != 6:
            raise ValueError("REFERENCE_IPV6_INVALID")
        header_length = 40
        length = 40 + struct.unpack_from("!H", frame, offset + 4)[0]
        proto = frame[offset + 6]
        src = str(ipaddress.IPv6Address(frame[offset + 8 : offset + 24]))
        dst = str(ipaddress.IPv6Address(frame[offset + 24 : offset + 40]))
    else:
        raise ValueError("REFERENCE_LINK_UNSUPPORTED")
    if offset + length > wire_length:
        raise ValueError("REFERENCE_WIRE_LENGTH")
    start = offset + header_length
    if proto not in (6, 17):
        raise ValueError("REFERENCE_TRANSPORT_UNSUPPORTED")
    minimum = 20 if proto == 6 else 8
    if len(frame) < start + minimum or length < header_length + minimum:
        raise ValueError("REFERENCE_TRANSPORT_TRUNCATED")
    sport, dport = struct.unpack_from("!HH", frame, start)
    if proto == 6:
        sequence, ack = struct.unpack_from("!II", frame, start + 4)
        transport_length = (frame[start + 12] >> 4) * 4
        if (
            transport_length < 20
            or start + transport_length > len(frame)
            or header_length + transport_length > length
        ):
            raise ValueError("REFERENCE_TCP_HEADER")
        flags = ((frame[start + 12] & 1) << 8) | frame[start + 13]
    else:
        transport_length = 8
        sequence = ack = None
        flags = 0
        if struct.unpack_from("!H", frame, start + 4)[0] != length - header_length:
            raise ValueError("REFERENCE_UDP_LENGTH")
    payload_length = length - header_length - transport_length
    complete = len(frame) >= offset + length
    payload = frame[start + transport_length : offset + length]
    return WirePacket(
        index,
        timestamp_ns,
        ((src, sport), (dst, dport)),
        "tcp" if proto == 6 else "udp",
        length,
        flags,
        sequence,
        ack,
        payload_length,
        hashlib.sha256(payload).hexdigest(),
        complete,
    )


def read_reference(
    path: Path, expected_sha256: str
) -> tuple[dict[int, WirePacket], dict[str, int]]:
    if (
        path.is_symlink()
        or not path.is_file()
        or not 24 <= path.stat().st_size <= 256 * 1024**2
    ):
        raise ValueError("REFERENCE_FILE_INVALID")
    packets = {}
    counts = Counter()
    sha = hashlib.sha256()
    with path.open("rb") as stream:

        def read(size: int) -> bytes:
            data = stream.read(size)
            sha.update(data)
            counts["bytes_read"] += len(data)
            return data

        header = read(24)
        formats = {
            b"\xd4\xc3\xb2\xa1": ("<", 1000),
            b"\xa1\xb2\xc3\xd4": (">", 1000),
            b"\x4d\x3c\xb2\xa1": ("<", 1),
            b"\xa1\xb2\x3c\x4d": (">", 1),
        }
        if header[:4] not in formats:
            raise ValueError("REFERENCE_CLASSIC_PCAP_REQUIRED")
        order, factor = formats[header[:4]]
        major, minor, zone, _, snaplen, link = struct.unpack(
            order + "HHiiII", header[4:]
        )
        if (major, minor, zone, link) != (2, 4, 0, 1) or not 1 <= snaplen <= 262144:
            raise ValueError("REFERENCE_PCAP_HEADER")
        while record := read(16):
            if len(record) != 16:
                raise ValueError("REFERENCE_RECORD_TRUNCATED")
            seconds, sub, captured, wire = struct.unpack(order + "IIII", record)
            if not 0 < captured <= min(snaplen, wire) or sub >= 1_000_000_000 // factor:
                raise ValueError("REFERENCE_RECORD_INVALID")
            frame = read(captured)
            if len(frame) != captured:
                raise ValueError("REFERENCE_FRAME_TRUNCATED")
            counts["raw_packets"] += 1
            try:
                decoded = decode_frame(
                    counts["raw_packets"],
                    seconds * 1_000_000_000 + sub * factor,
                    frame,
                    wire,
                )
            except ValueError as exc:
                counts[str(exc)] += 1
                continue
            packets[decoded.index] = decoded
            counts["parsed_packets"] += 1
            counts["flags:" + str(decoded.flags)] += 1
            if not decoded.complete:
                counts["truncated_packets"] += 1
    if sha.hexdigest() != expected_sha256:
        raise ValueError("REFERENCE_SOURCE_DIGEST_MISMATCH")
    return packets, dict(counts)


def partition_reference(
    records: tuple[WirePacket, ...], connections: tuple
) -> dict[str, object]:
    """Row-first independent count table from wire bytes, not production Packets.

    Missing interval is only an exact singleton observation, never imputed duration.
    This reference supplies no label, matching authority or training permission.
    """
    used = Counter()
    table = []
    for row in connections:
        selected = tuple(
            r
            for r in records
            if (
                r.timestamp_ns == row.start_ns
                if row.end_ns is None
                else row.start_ns <= r.timestamp_ns <= row.end_ns
            )
        )
        if not selected or min(r.timestamp_ns for r in selected) != row.start_ns:
            return {"status": "FAIL", "reason": "REFERENCE_START"}
        if row.end_ns is None:
            if len(selected) != 1:
                return {"status": "FAIL", "reason": "REFERENCE_SINGLETON"}
        elif max(r.timestamp_ns for r in selected) != row.end_ns:
            return {"status": "FAIL", "reason": "REFERENCE_END"}
        amounts = [0, 0, 0, 0]
        for r in selected:
            if (
                r.transport != row.key[0]
                or tuple(sorted(r.endpoints)) != row.key[1]
                or not r.complete
            ):
                return {"status": "FAIL", "reason": "REFERENCE_ENDPOINT_OR_TRUNCATION"}
            i = 0 if r.endpoints[0] == row.orig else 2
            amounts[i] += 1
            amounts[i + 1] += r.ip_length
            used[r.index] += 1
        if tuple(amounts) != row.counts:
            return {"status": "FAIL", "reason": "REFERENCE_COUNTER"}
        table.append(
            {
                "label_reference": row.reference,
                "packet_count": len(selected),
                "actual_counts": amounts,
                "expected_counts": list(row.counts),
            }
        )
    if len(used) != len(records) or any(used[r.index] != 1 for r in records):
        return {"status": "FAIL", "reason": "REFERENCE_NOT_EXACT_PARTITION"}
    return {
        "status": "PASS",
        "method": "independent wire decoder; row-first count table; disjoint exhaustive coverage",
        "connection_counters": table,
    }
