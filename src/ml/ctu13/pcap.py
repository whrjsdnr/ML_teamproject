"""Ethernet classic PCAP / PCAPNG header reader. Retains metadata, never payloads."""

import hashlib
import ipaddress
import struct
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from ml.verified_producers.network import Packet


class ChunkReader:
    def __init__(self, chunks: Iterable[bytes]):
        self.chunks = iter(chunks)
        self.buffer = bytearray()
        self.bytes_read = 0
        self.sha = hashlib.sha256()

    def read(self, size: int, *, eof: bool = False) -> bytes:
        while len(self.buffer) < size:
            try:
                chunk = next(self.chunks)
            except StopIteration:
                if eof and not self.buffer:
                    return b""
                raise ValueError("PCAP_TRUNCATED") from None
            self.bytes_read += len(chunk)
            self.sha.update(chunk)
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result


@dataclass(frozen=True)
class Record:
    index: int
    timestamp_ns: int
    captured_length: int
    wire_length: int
    header: bytes


class PcapReader:
    def __init__(self, chunks: Iterable[bytes]):
        self.reader = ChunkReader(chunks)
        magic = self.reader.read(4)
        self.format = "PCAPNG" if magic == b"\x0a\x0d\x0d\x0a" else "PCAP"
        self.interfaces: list[tuple[int, int]] = []
        self.blocks: dict[int, int] = {}
        self.factor = 1000
        self.snaplen = 65535
        if self.format == "PCAPNG":
            length_and_order = self.reader.read(8)
            order = length_and_order[4:]
            if order not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
                raise ValueError("PCAPNG_BYTE_ORDER")
            self.endian = "<" if order[0] == 0x4D else ">"
            size = struct.unpack(self.endian + "I", length_and_order[:4])[0]
            if not 28 <= size <= 1048576 or size % 4:
                raise ValueError("PCAPNG_BLOCK_LIMIT")
            tail = self.reader.read(size - 12)
            if struct.unpack(self.endian + "I", tail[-4:])[0] != size or struct.unpack(
                self.endian + "HH", tail[:4]
            ) != (1, 0):
                raise ValueError("PCAPNG_SECTION_INVALID")
            return
        header = magic + self.reader.read(20)
        formats = {
            b"\xd4\xc3\xb2\xa1": ("<", 1000),
            b"\xa1\xb2\xc3\xd4": (">", 1000),
            b"\x4d\x3c\xb2\xa1": ("<", 1),
            b"\xa1\xb2\x3c\x4d": (">", 1),
        }
        if header[:4] not in formats:
            raise ValueError("PCAP_FORMAT_UNSUPPORTED")
        self.endian, self.factor = formats[header[:4]]
        major, minor, timezone_offset, _, self.snaplen, link = struct.unpack(
            self.endian + "HHiiII", header[4:]
        )
        if (
            (major, minor) != (2, 4)
            or timezone_offset != 0
            or link != 1
            or not 1 <= self.snaplen <= 262144
        ):
            raise ValueError("PCAP_HEADER_UNSUPPORTED")

    def __iter__(self) -> Iterator[Record]:
        if self.format == "PCAPNG":
            yield from self._pcapng()
            return
        index = 0
        while header := self.reader.read(16, eof=True):
            seconds, sub, captured, wire = struct.unpack(self.endian + "IIII", header)
            if sub >= 1_000_000_000 // self.factor or not 0 < captured <= min(
                self.snaplen, wire
            ):
                raise ValueError("PCAP_RECORD_INVALID")
            data = self.reader.read(captured)
            index += 1
            # Only the bounded headers needed by the parser survive this iterator yield.
            yield Record(
                index,
                (seconds * 1_000_000_000) + sub * self.factor,
                captured,
                wire,
                data[:256],
            )

    def _pcapng(self) -> Iterator[Record]:
        index = 0
        while header := self.reader.read(8, eof=True):
            kind, size = struct.unpack(self.endian + "II", header)
            if not 12 <= size <= 1048576 or size % 4:
                raise ValueError("PCAPNG_BLOCK_LIMIT")
            block = self.reader.read(size - 8)
            if struct.unpack(self.endian + "I", block[-4:])[0] != size:
                raise ValueError("PCAPNG_BLOCK_TRAILER")
            self.blocks[kind] = self.blocks.get(kind, 0) + 1
            body = block[:-4]
            if kind == 0x0A0D0D0A:
                raise ValueError("PCAPNG_MULTIPLE_SECTIONS_UNSUPPORTED")
            if kind == 1:
                if len(body) < 8 or len(self.interfaces) >= 16:
                    raise ValueError("PCAPNG_INTERFACE_LIMIT")
                link, _, snap = struct.unpack(self.endian + "HHI", body[:8])
                if link != 1 or not 1 <= snap <= 262144:
                    raise ValueError("PCAPNG_INTERFACE_UNSUPPORTED")
                factor = 1000
                offset = 8
                seen = set()
                while offset < len(body):
                    if offset + 4 > len(body):
                        raise ValueError("PCAPNG_OPTION_TRUNCATED")
                    code, length = struct.unpack(
                        self.endian + "HH", body[offset : offset + 4]
                    )
                    offset += 4
                    if offset + length > len(body):
                        raise ValueError("PCAPNG_OPTION_TRUNCATED")
                    value = body[offset : offset + length]
                    offset += (length + 3) // 4 * 4
                    if code == 0:
                        if length or any(body[offset:]):
                            raise ValueError("PCAPNG_OPTION_INVALID")
                        break
                    if code in (9, 14):
                        if code in seen:
                            raise ValueError("PCAPNG_DUPLICATE_CLOCK_OPTION")
                        seen.add(code)
                    if code == 9:
                        if length != 1 or value[0] > 9:
                            raise ValueError("PCAPNG_CLOCK_UNSUPPORTED")
                        factor = 10 ** (9 - value[0])
                    if code == 14 and (length != 8 or any(value)):
                        raise ValueError("PCAPNG_CLOCK_OFFSET_UNSUPPORTED")
                self.interfaces.append((snap, factor))
                self.snaplen, self.factor = snap, factor
            elif kind == 6:
                if len(body) < 20:
                    raise ValueError("PCAPNG_PACKET_TRUNCATED")
                interface, high, low, captured, wire = struct.unpack(
                    self.endian + "IIIII", body[:20]
                )
                if interface >= len(self.interfaces):
                    raise ValueError("PCAPNG_INTERFACE_UNKNOWN")
                snap, factor = self.interfaces[interface]
                if (
                    not 0 < captured <= min(snap, wire)
                    or len(body) < 20 + (captured + 3) // 4 * 4
                ):
                    raise ValueError("PCAPNG_PACKET_INVALID")
                index += 1
                yield Record(
                    index,
                    ((high << 32) | low) * factor,
                    captured,
                    wire,
                    body[20 : 20 + min(captured, 256)],
                )
            elif kind in (2, 3):
                raise ValueError("PCAPNG_TIMESTAMP_PACKET_UNSUPPORTED")


def parse_packet(record: Record, source_identity: str) -> Packet:
    data = record.header
    if len(data) < 14:
        raise ValueError("ETHERNET_TRUNCATED")
    layer = 14
    kind = int.from_bytes(data[12:14], "big")
    if kind in (0x8100, 0x88A8):
        if len(data) < 18:
            raise ValueError("VLAN_TRUNCATED")
        kind = int.from_bytes(data[16:18], "big")
        layer = 18
    if kind == 0x0800:
        if len(data) < layer + 20 or data[layer] >> 4 != 4:
            raise ValueError("IPV4_TRUNCATED")
        ihl = (data[layer] & 15) * 4
        length = int.from_bytes(data[layer + 2 : layer + 4], "big")
        if ihl < 20 or length < ihl or len(data) < layer + ihl:
            raise ValueError("IPV4_INVALID")
        if int.from_bytes(data[layer + 6 : layer + 8], "big") & 0x3FFF:
            raise ValueError("IP_FRAGMENT_UNSUPPORTED")
        protocol = data[layer + 9]
        src = str(ipaddress.ip_address(data[layer + 12 : layer + 16]))
        dst = str(ipaddress.ip_address(data[layer + 16 : layer + 20]))
        transport_offset = layer + ihl
    elif kind == 0x86DD:
        if len(data) < layer + 40 or data[layer] >> 4 != 6:
            raise ValueError("IPV6_TRUNCATED")
        length = 40 + int.from_bytes(data[layer + 4 : layer + 6], "big")
        protocol = data[layer + 6]
        src = str(ipaddress.ip_address(data[layer + 8 : layer + 24]))
        dst = str(ipaddress.ip_address(data[layer + 24 : layer + 40]))
        transport_offset = layer + 40
    else:
        raise ValueError("LINK_PROTOCOL_UNSUPPORTED")
    if protocol not in (6, 17):
        raise ValueError("TRANSPORT_UNSUPPORTED")
    minimum = 20 if protocol == 6 else 8
    if (
        length + layer > record.wire_length
        or len(data) < transport_offset + minimum
        or length < transport_offset - layer + minimum
    ):
        raise ValueError("TRANSPORT_HEADER_TRUNCATED")
    if protocol == 6:
        tcp_length = (data[transport_offset + 12] >> 4) * 4
        if tcp_length < 20 or length < transport_offset - layer + tcp_length:
            raise ValueError("TCP_HEADER_INVALID")
        flags = data[transport_offset + 13] | ((data[transport_offset + 12] & 1) << 8)
    else:
        udp_length = int.from_bytes(
            data[transport_offset + 4 : transport_offset + 6], "big"
        )
        if udp_length < 8 or udp_length != length - (transport_offset - layer):
            raise ValueError("UDP_LENGTH_INVALID")
        flags = 0
    sport, dport = struct.unpack("!HH", data[transport_offset : transport_offset + 4])
    return Packet(
        f"{source_identity}:{record.index}",
        source_identity,
        source_identity,
        record.timestamp_ns,
        src,
        dst,
        sport,
        dport,
        "tcp" if protocol == 6 else "udp",
        length,
        flags,
    )
