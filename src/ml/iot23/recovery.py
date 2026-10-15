"""Exact externally referenced SYN-only partition; existing flows/features unchanged.

No guessed Zeek timeout, clock tolerance, dropped/relabelled packet or 1:1 fiction.
"""

from dataclasses import asdict, dataclass
from itertools import pairwise

from ml.ctu13.flows import Flow
from ml.iot23.wire_reference import WirePacket, partition_reference
from ml.iot23.zeek import Connection, Labels, bind
from ml.verified_producers.contracts import digest
from ml.verified_producers.network import Packet


def policy() -> dict[str, object]:
    return {
        "id": "iot23-exact-syn-partition:v1",
        "clock_shift_ns": 0,
        "counter_tolerance": 0,
        "flow_segmentation": "UNCHANGED_NETWORK14_30S_IDLE_120S_ACTIVE",
        "allowed_recovery": "SYN_ONLY_IDENTICAL_SEQUENCE_ZERO_PAYLOAD_ZERO_ACK",
        "missing_duration": "SINGLE_PACKET_EXACT_START_AND_COUNTS_ONLY_NO_IMPUTATION",
        "mapping": "DISJOINT_EXHAUSTIVE_PACKET_PARTITION_ALL_LABELS_CONCORDANT",
        "test_session": "34-1_SEALED_NOT_FOR_RULE_SELECTION",
        "authority": "NO_TRAINING_OR_OPERATIONAL_PROMOTION",
    }


@dataclass(frozen=True)
class BindingResult:
    status: str
    reason: str
    references: tuple[str, ...]
    label: str | None
    cardinality: str
    proof_digest: str | None = None


def wire_matches(packet: Packet, wire: WirePacket, source: str) -> bool:
    return (
        packet.event_id == f"{source}:{wire.index}"
        and packet.interface_id == source
        and packet.capture_session_id == source
        and packet.timestamp_ns == wire.timestamp_ns
        and packet.endpoints == wire.endpoints
        and packet.transport == wire.transport
        and packet.ip_length == wire.ip_length
        and packet.tcp_flags == wire.flags
        and wire.complete
    )


def _counts(packets: tuple[Packet, ...], row: Connection) -> tuple[int, int, int, int]:
    orig = tuple(p for p in packets if p.endpoints[0] == row.orig)
    resp = tuple(p for p in packets if p.endpoints[0] != row.orig)
    return (
        len(orig),
        sum(p.ip_length for p in orig),
        len(resp),
        sum(p.ip_length for p in resp),
    )


def recover(flow: Flow, labels: Labels, wire: dict[int, WirePacket]) -> BindingResult:
    packets = flow.packets
    status, row, reason = bind(packets, labels)
    old = BindingResult(
        status,
        reason,
        (row.reference,) if row else (),
        row.label if row else None,
        "BASELINE",
    )
    if flow.incomplete:
        return BindingResult(
            "EXCLUDED",
            flow.reason or flow.closure,
            old.references,
            old.label,
            "BASELINE",
        )
    if status == "VERIFIED_MATCH":
        return old
    if (
        status not in {"CANDIDATE_MATCH", "EXCLUDED"}
        or not packets
        or packets[0].transport != "tcp"
    ):
        return old
    if reason not in {
        "ZEEK_DURATION_DOES_NOT_CONTAIN_ALL_PACKETS",
        "MISSING_LABEL_DURATION",
    }:
        return old
    if labels.counts.get("duplicate_uid", 0):
        return BindingResult(
            "AMBIGUOUS",
            "DUPLICATE_UID_IN_LABEL_SOURCE",
            old.references,
            old.label,
            "UNVERIFIED",
        )
    first = packets[0]
    source = labels.session
    independent = []
    for packet in packets:
        try:
            index = int(packet.event_id.rsplit(":", 1)[1])
            ref = wire[index]
        except (KeyError, ValueError, IndexError):
            return BindingResult(
                status,
                "INDEPENDENT_REFERENCE_UNAVAILABLE",
                old.references,
                old.label,
                "UNVERIFIED",
            )
        if not wire_matches(packet, ref, source):
            return BindingResult(
                "EXCLUDED",
                "INDEPENDENT_PACKET_MISMATCH",
                old.references,
                old.label,
                "UNVERIFIED",
            )
        independent.append(ref)
    if any(
        r.flags != 2
        or r.payload_length
        or r.acknowledgment != 0
        or r.endpoints != first.endpoints
        for r in independent
    ):
        return old
    if len({r.sequence for r in independent}) != 1:
        return BindingResult(
            status,
            "CONNECTION_REUSE_SEQUENCE_CHANGE",
            old.references,
            old.label,
            "UNVERIFIED",
        )
    if len({p.event_id for p in packets}) != len(packets) or any(
        a.timestamp_ns >= b.timestamp_ns for a, b in pairwise(packets)
    ):
        return BindingResult(
            "EXCLUDED",
            "DUPLICATE_OR_NON_UNIQUE_PACKET_TIME",
            old.references,
            old.label,
            "UNVERIFIED",
        )
    key = first.transport, tuple(sorted(first.endpoints))
    candidates = tuple(
        r
        for r in labels.rows.get(key, ())
        if r.start_ns <= packets[-1].timestamp_ns
        and (
            r.start_ns >= first.timestamp_ns
            or (r.end_ns is not None and r.end_ns >= first.timestamp_ns)
        )
    )
    if (
        not candidates
        or len({r.uid for r in candidates}) != len(candidates)
        or len({r.reference for r in candidates}) != len(candidates)
    ):
        return BindingResult(
            "AMBIGUOUS",
            "DUPLICATE_CONNECTION_REFERENCE",
            old.references,
            old.label,
            "UNVERIFIED",
        )
    assigned = {r.reference: [] for r in candidates}
    for packet in packets:
        matches = [
            r
            for r in candidates
            if r.session == source
            and (
                r.start_ns == packet.timestamp_ns
                if r.end_ns is None
                else r.start_ns <= packet.timestamp_ns <= r.end_ns
            )
        ]
        if len(matches) != 1:
            return BindingResult(
                "AMBIGUOUS" if len(matches) > 1 else status,
                "NON_UNIQUE_OR_UNCOVERED_PACKET",
                old.references,
                old.label,
                "UNVERIFIED",
            )
        assigned[matches[0].reference].append(packet)
    for r in candidates:
        group = tuple(assigned[r.reference])
        if (
            not group
            or group[0].timestamp_ns != r.start_ns
            or r.counts is None
            or _counts(group, r) != r.counts
        ):
            return BindingResult(
                status,
                "EXACT_PARTITION_COUNTER_MISMATCH",
                old.references,
                old.label,
                "UNVERIFIED",
            )
        if (r.end_ns is None and len(group) != 1) or (
            r.end_ns is not None and group[-1].timestamp_ns != r.end_ns
        ):
            return BindingResult(
                status,
                "EXACT_PARTITION_TIME_MISMATCH",
                old.references,
                old.label,
                "UNVERIFIED",
            )
        if r.missed_bytes != 0 or r.label not in {"Benign", "Malicious"}:
            return BindingResult(
                "EXCLUDED",
                "PARTITION_QUALITY_OR_LABEL_UNVERIFIED",
                old.references,
                old.label,
                "UNVERIFIED",
            )
    if len({(r.label, r.detailed) for r in candidates}) != 1:
        return BindingResult(
            "AMBIGUOUS",
            "CONFLICTING_PARTITION_LABELS",
            old.references,
            None,
            "UNVERIFIED",
        )
    independent_check = partition_reference(tuple(independent), candidates)
    if independent_check["status"] != "PASS":
        return BindingResult(
            status,
            "INDEPENDENT_PARTITION_DISAGREEMENT",
            old.references,
            old.label,
            "UNVERIFIED",
        )
    refs = tuple(r.reference for r in sorted(candidates, key=lambda r: r.start_ns))
    proof = digest(
        {
            "policy": policy(),
            "independent_partition": independent_check,
            "source": source,
            "label_sha": labels.label_sha256,
            "packets": [asdict(p) for p in packets],
            "wire": [asdict(r) for r in independent],
            "partition": {
                k: [p.event_id for p in v] for k, v in sorted(assigned.items())
            },
            "references": refs,
        }
    )
    return BindingResult(
        "VERIFIED_MATCH",
        "EXACT_SYN_PACKET_PARTITION",
        refs,
        candidates[0].label,
        f"{len(refs)}_ZEEK_CONNECTIONS_TO_1_UNCHANGED_PRODUCER_FLOW",
        proof,
    )
