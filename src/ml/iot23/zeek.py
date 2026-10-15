"""Strict observed IoT-23 Zeek TSV + triple-space analyst suffix parser."""

import hashlib
import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from itertools import pairwise
from pathlib import Path

from ml.verified_producers.contracts import digest
from ml.verified_producers.network import Packet

FIELDS = (
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "local_orig",
    "local_resp",
    "missed_bytes",
    "history",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
    "tunnel_parents",
    "label",
    "detailed-label",
)
TYPES = (
    "time",
    "string",
    "addr",
    "port",
    "addr",
    "port",
    "enum",
    "string",
    "interval",
    "count",
    "count",
    "string",
    "bool",
    "bool",
    "count",
    "string",
    "count",
    "count",
    "count",
    "count",
    "set[string]",
    "string",
    "string",
)


def columns(line: str) -> tuple[str, ...]:
    cells = line.rstrip("\n").split("\t")
    # Exact publisher extension. Do not generically split whitespace in raw fields.
    if len(cells) == 21:
        cells = cells[:-1] + cells[-1].split("   ")
    if len(cells) != 23 or any(not c for c in cells):
        raise ValueError("ZEEK_SCHEMA_WIDTH")
    return tuple(cells)


def epoch_ns(value: str) -> int:
    number = Decimal(value)
    scaled = number * 1_000_000_000
    if not number.is_finite() or not 0 <= scaled <= 2**63 - 1 or scaled != int(scaled):
        raise ValueError("INVALID_EPOCH_OR_DURATION")
    return int(scaled)


@dataclass(frozen=True)
class Connection:
    reference: str
    uid: str
    session: str
    key: tuple[object, ...]
    orig: tuple[str, int]
    start_ns: int
    end_ns: int | None
    label: str
    detailed: str
    counts: tuple[int, int, int, int] | None
    missed_bytes: int | None


@dataclass(frozen=True)
class Labels:
    rows: dict[tuple[object, ...], tuple[Connection, ...]]
    counts: dict[str, int]
    schema_digest: str
    label_sha256: str
    session: str


def load(path: Path, expected_sha256: str, session: str) -> Labels:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 32 * 1024**2:
        raise ValueError("LABEL_FILE_INVALID")
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected_sha256:
        raise ValueError("LABEL_DIGEST_MISMATCH")
    rows = defaultdict(list)
    counts = Counter()
    fields = types = None
    seen_uids = set()
    with path.open(encoding="ascii", newline="") as stream:
        if stream.readline() != "#separator \\x09\n":
            raise ValueError("ZEEK_SEPARATOR")
        for line in stream:
            if len(line) > 16384:
                raise ValueError("LABEL_LINE_LIMIT")
            if line.startswith("#fields\t"):
                fields = columns(line[8:])
                if fields not in (FIELDS, FIELDS[:-1] + ("det_label",)):
                    raise ValueError("ZEEK_FIELD_SCHEMA")
                continue
            if line.startswith("#types\t"):
                types = columns(line[7:])
                if types != TYPES:
                    raise ValueError("ZEEK_TYPE_SCHEMA")
                continue
            if line.startswith("#"):
                continue
            if fields not in (FIELDS, FIELDS[:-1] + ("det_label",)) or types != TYPES:
                raise ValueError("ZEEK_HEADER_REQUIRED")
            counts["total_rows"] += 1
            if counts["total_rows"] > 250000:
                raise ValueError("LABEL_ROW_LIMIT")
            values = columns(line)
            row = dict(zip(FIELDS, values, strict=True))
            counts["label:" + row["label"]] += 1
            counts["detail:" + row["detailed-label"]] += 1
            if row["proto"] not in {"tcp", "udp"}:
                counts["unsupported_protocol"] += 1
                continue
            try:
                start = epoch_ns(row["ts"])
                end = (
                    None
                    if row["duration"] == "-"
                    else start + epoch_ns(row["duration"])
                )
                src, dst = (
                    str(ipaddress.ip_address(row["id.orig_h"])),
                    str(ipaddress.ip_address(row["id.resp_h"])),
                )
                sport, dport = int(row["id.orig_p"]), int(row["id.resp_p"])
                if not 0 <= sport <= 65535 or not 0 <= dport <= 65535:
                    raise ValueError("PORT_INVALID")
                names = ("orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes")
                amounts = (
                    None
                    if any(row[n] == "-" for n in names)
                    else tuple(int(row[n]) for n in names)
                )
                missed = (
                    None if row["missed_bytes"] == "-" else int(row["missed_bytes"])
                )
                if (amounts and any(v < 0 for v in amounts)) or (
                    missed is not None and missed < 0
                ):
                    raise ValueError("NEGATIVE_COUNTER")
            except (ValueError, InvalidOperation, OverflowError):
                counts["invalid_row"] += 1
                continue
            if row["uid"] in seen_uids:
                counts["duplicate_uid"] += 1
            seen_uids.add(row["uid"])
            key = row["proto"], tuple(sorted(((src, sport), (dst, dport))))
            rows[key].append(
                Connection(
                    digest({"file": expected_sha256, "row": counts["total_rows"]}),
                    row["uid"],
                    session,
                    key,
                    (src, sport),
                    start,
                    end,
                    row["label"],
                    row["detailed-label"],
                    amounts,
                    missed,
                )
            )
    if fields not in (FIELDS, FIELDS[:-1] + ("det_label",)) or types != TYPES:
        raise ValueError("ZEEK_HEADER_REQUIRED")
    return Labels(
        {k: tuple(v) for k, v in rows.items()},
        dict(counts),
        digest(
            {"fields": fields, "types": TYPES, "suffix": "TAB_OR_EXACT_TRIPLE_SPACE"}
        ),
        expected_sha256,
        session,
    )


def bind(
    packets: tuple[Packet, ...], labels: Labels
) -> tuple[str, Connection | None, str]:
    if not packets or any(p.capture_session_id != labels.session for p in packets):
        return "EXCLUDED", None, "SESSION_BINDING"
    first = packets[0]
    key = first.transport, tuple(sorted(first.endpoints))
    if any(
        (p.transport, tuple(sorted(p.endpoints))) != key
        or p.interface_id != first.interface_id
        for p in packets
    ) or any(a.timestamp_ns > b.timestamp_ns for a, b in pairwise(packets)):
        return "EXCLUDED", None, "INVALID_FLOW"
    if any(r.session != labels.session for r in labels.rows.get(key, ())):
        return "EXCLUDED", None, "LABEL_SESSION_BINDING"
    matches = [
        r
        for r in labels.rows.get(key, ())
        if r.end_ns is not None
        and r.start_ns <= first.timestamp_ns <= packets[-1].timestamp_ns <= r.end_ns
    ]
    if not matches:
        # Diagnostic only: same first epoch and tuple cannot repair a missing
        # duration or widen Zeek's payload-oriented TCP duration to all packets.
        anchored = [
            r for r in labels.rows.get(key, ()) if r.start_ns == first.timestamp_ns
        ]
        if len(anchored) > 1:
            return "AMBIGUOUS", None, "MULTIPLE_START_ANCHORS"
        if len(anchored) == 1:
            row = anchored[0]
            if row.end_ns is None:
                return "EXCLUDED", row, "MISSING_LABEL_DURATION"
            return "CANDIDATE_MATCH", row, "ZEEK_DURATION_DOES_NOT_CONTAIN_ALL_PACKETS"
        return "UNMATCHED", None, "NO_EXACT_CONTAINING_INTERVAL"
    if len(matches) != 1:
        return "AMBIGUOUS", None, "MULTIPLE_LABEL_INTERVALS"
    row = matches[0]
    if row.label not in {"Benign", "Malicious"}:
        return "EXCLUDED", row, "UNKNOWN_LABEL"
    if row.missed_bytes != 0 or row.counts is None:
        return "EXCLUDED", row, "LABEL_CAPTURE_QUALITY"
    forward = [p for p in packets if p.endpoints[0] == row.orig]
    backward = [p for p in packets if p.endpoints[0] != row.orig]
    actual = (
        len(forward),
        sum(p.ip_length for p in forward),
        len(backward),
        sum(p.ip_length for p in backward),
    )
    if actual != row.counts or first.timestamp_ns != row.start_ns:
        return "CANDIDATE_MATCH", row, "CONNECTION_FRAGMENT_OR_COUNTER_MISMATCH"
    return (
        "VERIFIED_MATCH",
        row,
        "EXACT_EPOCH_TUPLE_COUNTS_FIRST_SEEN_ORIENTATION_RECORDED",
    )
