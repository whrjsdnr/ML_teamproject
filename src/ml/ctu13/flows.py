"""Bounded first-observed bidirectional segmentation, explicit incomplete closures."""

from collections import OrderedDict
from dataclasses import dataclass

from ml.ctu13.labels import flow_key
from ml.verified_producers.network import Packet


@dataclass(frozen=True)
class Flow:
    packets: tuple[Packet, ...]
    closure: str


class Flows:
    def __init__(self, *, max_active: int = 20000, max_buffered: int = 100000):
        if not 1 <= max_active <= 20000 or not 1 <= max_buffered <= 100000:
            raise ValueError("FLOW_RESOURCE_LIMIT")
        self.active: OrderedDict[tuple[object, ...], list[Packet]] = OrderedDict()
        self.max_active = max_active
        self.max_buffered = max_buffered
        self.buffered = 0
        self.watermark = -1

    def _close(self, key: tuple[object, ...], reason: str) -> Flow:
        packets = tuple(self.active.pop(key))
        self.buffered -= len(packets)
        return Flow(packets, reason)

    def add(self, packet: Packet) -> tuple[Flow, ...]:
        if packet.timestamp_ns < self.watermark:
            raise ValueError("LATE_PACKET_EXCLUDED")
        self.watermark = packet.timestamp_ns
        result = []
        # Ordered by last observation: bounded idle expiry, no full-table scan.
        while self.active:
            key = next(iter(self.active))
            if packet.timestamp_ns - self.active[key][-1].timestamp_ns < 30_000_000_000:
                break
            result.append(self._close(key, "IDLE_TIMEOUT"))
        key = flow_key(packet)
        if key in self.active:
            old = self.active[key]
            if (
                packet.capture_session_id != old[0].capture_session_id
                or packet.interface_id != old[0].interface_id
            ):
                raise ValueError("MIXED_CAPTURE_IDENTITY")
            if (
                packet.timestamp_ns - old[0].timestamp_ns >= 120_000_000_000
                or len(old) >= 4096
            ):
                result.append(
                    self._close(
                        key, "ACTIVE_TIMEOUT" if len(old) < 4096 else "PACKET_LIMIT"
                    )
                )
        while self.active and (
            len(self.active) >= self.max_active
            and key not in self.active
            or self.buffered >= self.max_buffered
        ):
            result.append(self._close(next(iter(self.active)), "RESOURCE_EVICTION"))
        self.active.setdefault(key, []).append(packet)
        self.active.move_to_end(key)
        self.buffered += 1
        return tuple(result)

    def finish(self, *, complete: bool) -> tuple[Flow, ...]:
        return tuple(
            self._close(key, "CAPTURE_END" if complete else "INCOMPLETE_CAPTURE")
            for key in list(self.active)
        )
