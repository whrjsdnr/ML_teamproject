"""Bounded lossless metadata compaction; Producer arithmetic remains unchanged."""

import sys
from array import array
from collections import Counter, OrderedDict
from dataclasses import dataclass

from ml.ctu13.labels import flow_key
from ml.verified_producers.contracts import digest
from ml.verified_producers.network import Packet


@dataclass(frozen=True)
class Flow:
    packets: tuple[Packet, ...]
    closure: str
    reason: str = ""

    @property
    def flow_id(self) -> str:
        return digest([p.event_id for p in self.packets])

    @property
    def incomplete(self) -> bool:
        return self.closure in {
            "RESOURCE_EVICTION",
            "INCOMPLETE_CAPTURE",
            "PACKET_LIMIT",
            "CAPTURE_GAP",
        }


class _PacketState:
    """Retain shared endpoints once; reconstruct the exact original Packet at flush.

    Integer arrays avoid online mean/variance approximations or producer changes.
    Charges conservatively bound retained containers, not total interpreter RSS.
    """

    def __init__(self, first: Packet):
        self.first = first
        self.samples = array("Q")
        self.event_ids: list[str] = []
        self.seen: set[str] = set()
        self.charge = (
            2048
            + sys.getsizeof(first)
            + sys.getsizeof(vars(first))
            + sum(sys.getsizeof(v) for v in vars(first).values())
        )

    def __len__(self) -> int:
        return len(self.event_ids)

    @property
    def last_ns(self) -> int:
        return self.samples[-3]

    @staticmethod
    def packet_charge(packet: Packet) -> int:
        # Array/list spare capacity, set load factor and ID string. Fixed upper
        # reserve per entry is deliberately larger than three uint64 values.
        return sys.getsizeof(packet.event_id) + 256

    def append(self, packet: Packet) -> None:
        if packet.event_id in self.seen:
            raise ValueError("DUPLICATE_EVENT")
        reverse = packet.endpoints != self.first.endpoints
        self.samples.extend(
            (
                packet.timestamp_ns,
                packet.ip_length,
                packet.tcp_flags | (int(reverse) << 9),
            )
        )
        self.event_ids.append(packet.event_id)
        self.seen.add(packet.event_id)
        self.charge += self.packet_charge(packet)

    def packets(self) -> tuple[Packet, ...]:
        result = []
        first = self.first
        for i, event_id in enumerate(self.event_ids):
            timestamp, length, packed = self.samples[i * 3 : i * 3 + 3]
            endpoints = first.endpoints[::-1] if packed & 512 else first.endpoints
            result.append(
                Packet(
                    event_id,
                    first.interface_id,
                    first.capture_session_id,
                    timestamp,
                    endpoints[0][0],
                    endpoints[1][0],
                    endpoints[0][1],
                    endpoints[1][1],
                    first.transport,
                    length,
                    packed & 511,
                )
            )
        return tuple(result)


class Flows:
    def __init__(
        self,
        *,
        max_active: int = 20000,
        max_buffered: int = 100000,
        max_state_bytes: int = 64 * 1024**2,
    ):
        if (
            type(max_active) is not int
            or type(max_buffered) is not int
            or not 1 <= max_active <= 20000
            or not 1 <= max_buffered <= 100000
            or type(max_state_bytes) is not int
            or not 4096 <= max_state_bytes <= 256 * 1024**2
        ):
            raise ValueError("FLOW_RESOURCE_LIMIT")
        self.active: OrderedDict[tuple[object, ...], _PacketState] = OrderedDict()
        self.max_active = max_active
        self.max_buffered = max_buffered
        self.max_state_bytes = max_state_bytes
        self.buffered = self.state_bytes = self.peak_state_bytes = 0
        self.watermark = -1
        self.identity: tuple[str, str] | None = None
        self.closed_counts: Counter[str] = Counter()
        self.reason_counts: Counter[str] = Counter()

    def _close(self, key: tuple[object, ...], reason: str, detail: str = "") -> Flow:
        state = self.active.pop(key)
        self.buffered -= len(state)
        self.state_bytes -= state.charge
        self.closed_counts[reason] += 1
        self.reason_counts[detail or reason] += 1
        return Flow(state.packets(), reason, detail or reason)

    def add(self, packet: Packet) -> tuple[Flow, ...]:
        if not isinstance(packet, Packet):
            raise TypeError("INVALID_PACKET_SCHEMA")
        identity = packet.interface_id, packet.capture_session_id
        if self.identity is not None and identity != self.identity:
            raise ValueError("MIXED_CAPTURE_IDENTITY")
        if packet.timestamp_ns < self.watermark:
            raise ValueError("LATE_PACKET_EXCLUDED")
        key = flow_key(packet)
        if key in self.active and packet.event_id in self.active[key].seen:
            raise ValueError("DUPLICATE_EVENT")
        new = _PacketState(packet)
        increment = _PacketState.packet_charge(packet)
        if new.charge + increment > self.max_state_bytes:
            raise ValueError("PACKET_EXCEEDS_STATE_BYTE_BUDGET")
        self.identity = identity
        self.watermark = packet.timestamp_ns
        result = []
        while self.active:
            oldest = next(iter(self.active))
            if packet.timestamp_ns - self.active[oldest].last_ns < 30_000_000_000:
                break
            result.append(self._close(oldest, "IDLE_TIMEOUT"))
        if key in self.active:
            old = self.active[key]
            if (
                packet.timestamp_ns - old.first.timestamp_ns >= 120_000_000_000
                or len(old) >= 4096
            ):
                result.append(
                    self._close(
                        key, "ACTIVE_TIMEOUT" if len(old) < 4096 else "PACKET_LIMIT"
                    )
                )
        while self.active:
            reason = (
                "MAX_ACTIVE_FLOWS"
                if key not in self.active and len(self.active) >= self.max_active
                else "MAX_BUFFERED_PACKETS"
                if self.buffered >= self.max_buffered
                else "STATE_BYTE_BUDGET"
                if self.state_bytes
                + increment
                + (new.charge if key not in self.active else 0)
                > self.max_state_bytes
                else None
            )
            if reason is None:
                break
            result.append(
                self._close(next(iter(self.active)), "RESOURCE_EVICTION", reason)
            )
        if key not in self.active:
            self.active[key] = new
            self.state_bytes += new.charge
        self.active[key].append(packet)
        self.active.move_to_end(key)
        self.state_bytes += increment
        self.peak_state_bytes = max(self.peak_state_bytes, self.state_bytes)
        self.buffered += 1
        return tuple(result)

    def mark_gap(self) -> tuple[Flow, ...]:
        return tuple(
            self._close(key, "CAPTURE_GAP", "OBSERVED_GAP") for key in list(self.active)
        )

    def finish(self, *, complete: bool) -> tuple[Flow, ...]:
        if type(complete) is not bool:
            raise ValueError("INVALID_COMPLETENESS")
        return tuple(
            self._close(key, "CAPTURE_END" if complete else "INCOMPLETE_CAPTURE")
            for key in list(self.active)
        )
