"""External Argus flow labels. Background and inbound-to labels stay UNKNOWN."""

import csv
import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path

from ml.verified_producers.contracts import digest
from ml.verified_producers.network import Packet


def flow_key(packet: Packet) -> tuple[object, ...]:
    return packet.transport, tuple(sorted(packet.endpoints))


@dataclass(frozen=True)
class Label:
    key: tuple[object, ...]
    start_ns: int
    end_ns: int
    classification: str
    reference: str
    direction: str


@dataclass(frozen=True)
class LabelIndex:
    rows: dict[tuple[object, ...], tuple[Label, ...]]
    counts: dict[str, int]
    clock_verified: bool
    session_identity: str
    label_identity: str


def load_labels(
    path: Path,
    *,
    label_identity: str,
    session_identity: str,
    utc_offset_seconds: int,
    clock_verified: bool = False,
) -> LabelIndex:
    """Offset is explicit, never selected by maximizing matches.

    clock_verified=False is the default: even a unique candidate cannot become
    training truth. Caller declaration alone is not independent clock evidence.
    """
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 32 * 1024**2:
        raise ValueError("LABEL_FILE_INVALID")
    import hashlib

    if hashlib.sha256(path.read_bytes()).hexdigest() != label_identity:
        raise ValueError("LABEL_DIGEST_MISMATCH")
    if abs(utc_offset_seconds) > 14 * 3600:
        raise ValueError("LABEL_CLOCK_INVALID")
    rows = defaultdict(list)
    counts = Counter()
    seen = set()
    with path.open(newline="", encoding="ascii") as stream:
        reader = csv.DictReader(stream)
        required = {
            "StartTime",
            "Dur",
            "Proto",
            "SrcAddr",
            "Sport",
            "Dir",
            "DstAddr",
            "Dport",
            "Label",
        }
        if not required.issubset(reader.fieldnames or ()):
            raise ValueError("LABEL_SCHEMA_INVALID")
        for index, row in enumerate(reader, 1):
            if index > 250000:
                raise ValueError("LABEL_ROW_LIMIT")
            counts["total_rows"] += 1
            if row["Proto"] not in ("tcp", "udp"):
                counts["unsupported_protocol"] += 1
                continue
            try:
                stamp = datetime.strptime(
                    row["StartTime"], "%Y/%m/%d %H:%M:%S.%f"
                ).replace(tzinfo=UTC)
                start = (
                    int(stamp.timestamp()) * 1_000_000_000
                    + stamp.microsecond * 1000
                    - utc_offset_seconds * 1_000_000_000
                )
                duration = Decimal(row["Dur"])
                if not duration.is_finite() or duration < 0:
                    raise ValueError("INVALID_DURATION")
                end = start + int(duration * 1_000_000_000)
                src, dst = (
                    str(ipaddress.ip_address(row["SrcAddr"])),
                    str(ipaddress.ip_address(row["DstAddr"])),
                )
                sport, dport = int(row["Sport"]), int(row["Dport"])
                if not 0 <= sport <= 65535 or not 0 <= dport <= 65535:
                    raise ValueError("INVALID_PORT")
            except (ValueError, InvalidOperation, OverflowError):
                counts["invalid_row"] += 1
                continue
            raw_label = row["Label"]
            # Anchored publisher labels, not substring matching.
            classification = (
                "BOTNET"
                if raw_label.startswith("flow=From-Botnet-V48-")
                else "NORMAL"
                if raw_label.startswith("flow=From-Normal-V48-")
                else "UNKNOWN"
            )
            counts[classification] += 1
            key = row["Proto"], tuple(sorted(((src, sport), (dst, dport))))
            identity = (key, start, end, raw_label, row["Dir"])
            if identity in seen:
                counts["duplicate_rows"] += 1
            seen.add(identity)
            rows[key].append(
                Label(
                    key,
                    start,
                    end,
                    classification,
                    digest({"label_sha256": label_identity, "row": index}),
                    row["Dir"],
                )
            )
    return LabelIndex(
        {k: tuple(v) for k, v in rows.items()},
        dict(counts),
        clock_verified,
        session_identity,
        label_identity,
    )


def bind(packets: tuple[Packet, ...], labels: LabelIndex) -> tuple[str, Label | None]:
    if not packets or any(
        p.capture_session_id != labels.session_identity for p in packets
    ):
        return "SESSION_MISMATCH", None
    candidates = [
        label
        for label in labels.rows.get(flow_key(packets[0]), ())
        if label.start_ns
        <= packets[0].timestamp_ns
        <= packets[-1].timestamp_ns
        <= label.end_ns
    ]
    if not candidates:
        return "UNMATCHED", None
    if len(candidates) != 1:
        return "AMBIGUOUS", None
    result = candidates[0]
    if result.classification == "UNKNOWN":
        return "UNKNOWN_LABEL", result
    if not labels.clock_verified:
        return "CLOCK_UNVERIFIED", result
    return "MATCHED", result
