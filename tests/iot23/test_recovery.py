"""Independent byte reference + label partition without changing Feature14 flows."""

import hashlib
import struct
from dataclasses import replace

import pytest

from ml.ctu13.flows import Flow
from ml.iot23.recovery import policy, recover
from ml.iot23.wire_reference import WirePacket, decode_frame, read_reference
from ml.iot23.zeek import Connection, Labels
from ml.verified_producers.contracts import digest
from ml.verified_producers.network import Packet
from ml.verified_producers.network_v1_1 import network_features

SOURCE = "a" * 64


def case():
    times = (0, 1, 3, 7, 15, 32)
    ps = tuple(
        Packet(
            f"{SOURCE}:{i + 1}",
            SOURCE,
            SOURCE,
            (t + 1) * 10**9,
            "192.0.2.1",
            "192.0.2.2",
            2000,
            443,
            "tcp",
            60,
            2,
        )
        for i, t in enumerate(times)
    )
    key = ("tcp", tuple(sorted(ps[0].endpoints)))
    rows = tuple(
        Connection(
            f"ref{i}",
            f"uid{i}",
            SOURCE,
            key,
            ps[0].endpoints[0],
            ps[start].timestamp_ns,
            None if end is None else ps[end].timestamp_ns,
            "Malicious",
            "C&C",
            (count, 60 * count, 0, 0),
            0,
        )
        for i, (start, end, count) in enumerate(
            ((0, 2, 3), (3, None, 1), (4, None, 1), (5, None, 1))
        )
    )
    labels = Labels({key: rows}, {}, "schema", "b" * 64, SOURCE)
    wire = {
        i + 1: WirePacket(
            i + 1,
            p.timestamp_ns,
            p.endpoints,
            "tcp",
            60,
            2,
            100,
            0,
            0,
            hashlib.sha256(b"").hexdigest(),
            True,
        )
        for i, p in enumerate(ps)
    }
    return Flow(ps, "IDLE_TIMEOUT"), labels, wire


def change_label(labels, index, **kwargs):
    key = next(iter(labels.rows))
    rows = list(labels.rows[key])
    rows[index] = replace(rows[index], **kwargs)
    return replace(labels, rows={key: tuple(rows)})


def test_exact_multi_label_partition_keeps_whole_original_flow():
    flow, labels, wire = case()
    before = network_features(
        flow.packets, source_origin="OFFLINE_PCAP", source_identity=SOURCE
    )
    result = recover(flow, labels, wire)
    assert result.status == "VERIFIED_MATCH" and result.label == "Malicious"
    assert result.references == ("ref0", "ref1", "ref2", "ref3")
    assert result.cardinality == "4_ZEEK_CONNECTIONS_TO_1_UNCHANGED_PRODUCER_FLOW"
    assert result.proof_digest and result == recover(
        flow, labels, wire
    )  # determinism only, not independent proof
    after = network_features(
        flow.packets, source_origin="OFFLINE_PCAP", source_identity=SOURCE
    )
    assert before == after and len(flow.packets) == 6
    assert (
        labels.rows[next(iter(labels.rows))][1].end_ns is None
    )  # Never impute missing duration.


@pytest.mark.parametrize(
    "kwargs,status",
    [
        ({"label": "Benign"}, "AMBIGUOUS"),
        ({"label": "Background"}, "EXCLUDED"),
        ({"label": "Unknown"}, "EXCLUDED"),
        ({"missed_bytes": 1}, "EXCLUDED"),
        ({"missed_bytes": None}, "EXCLUDED"),
        ({"counts": (2, 120, 0, 0)}, "CANDIDATE_MATCH"),
        ({"counts": (1, 59, 0, 0)}, "CANDIDATE_MATCH"),
        ({"start_ns": 8_000_000_001}, "CANDIDATE_MATCH"),
        ({"session": "forged"}, "EXCLUDED"),
        ({"uid": "uid0"}, "AMBIGUOUS"),
        ({"reference": "ref0"}, "AMBIGUOUS"),
    ],
)
def test_no_time_counter_label_or_identity_relaxation(kwargs, status):
    flow, labels, wire = case()
    result = recover(flow, change_label(labels, 1, **kwargs), wire)
    assert result.status == status


def test_ambiguous_overlap_and_boundary():
    flow, labels, wire = case()
    assert (
        recover(flow, change_label(labels, 0, end_ns=8 * 10**9), wire).status
        == "AMBIGUOUS"
    )
    assert (
        recover(flow, change_label(labels, 0, end_ns=4 * 10**9 + 1), wire).status
        == "CANDIDATE_MATCH"
    )
    assert policy()["clock_shift_ns"] == policy()["counter_tolerance"] == 0


@pytest.mark.parametrize(
    "flags,payload", [(16, 0), (1, 0), (17, 0), (4, 0), (18, 0), (24, 3)]
)
def test_ack_fin_rst_or_data_never_promoted_by_syn_only_rule(flags, payload):
    flow, labels, wire = case()
    ps = list(flow.packets)
    ps[-1] = replace(ps[-1], tcp_flags=flags)
    wire[6] = replace(wire[6], flags=flags, payload_length=payload)
    assert (
        recover(replace(flow, packets=tuple(ps)), labels, wire).status
        != "VERIFIED_MATCH"
    )


def test_retransmission_counted_and_sequence_reuse_rejected():
    flow, labels, wire = case()
    assert (
        recover(flow, change_label(labels, 0, counts=(2, 120, 0, 0)), wire).status
        != "VERIFIED_MATCH"
    )
    wire[4] = replace(wire[4], sequence=999)
    assert recover(flow, labels, wire).reason == "CONNECTION_REUSE_SEQUENCE_CHANGE"


@pytest.mark.parametrize(
    "kind", ["missing", "endpoint", "time", "flags", "source", "truncated"]
)
def test_independent_reference_required(kind):
    flow, labels, wire = case()
    if kind == "missing":
        wire.pop(2)
    elif kind == "endpoint":
        wire[2] = replace(wire[2], endpoints=wire[2].endpoints[::-1])
    elif kind == "time":
        wire[2] = replace(wire[2], timestamp_ns=wire[2].timestamp_ns + 1)
    elif kind == "flags":
        wire[2] = replace(wire[2], flags=16)
    elif kind == "truncated":
        wire[2] = replace(wire[2], complete=False)
    else:
        flow = replace(
            flow,
            packets=(replace(flow.packets[0], event_id="forged:1"), *flow.packets[1:]),
        )
    assert recover(flow, labels, wire).status != "VERIFIED_MATCH"


def test_gap_and_limit_cannot_be_recovered():
    flow, labels, wire = case()
    for closure in (
        "CAPTURE_GAP",
        "RESOURCE_EVICTION",
        "PACKET_LIMIT",
        "INCOMPLETE_CAPTURE",
    ):
        assert (
            recover(replace(flow, closure=closure), labels, wire).status == "EXCLUDED"
        )


def test_existing_verified_bindings_remain_unchanged():
    flow, labels, _wire = case()
    row = labels.rows[next(iter(labels.rows))][0]
    short = replace(flow, packets=flow.packets[:3])
    labels = replace(labels, rows={row.key: (row,)})
    result = recover(short, labels, {})
    assert (
        result.status == "VERIFIED_MATCH"
        and result.reason != "EXACT_SYN_PACKET_PARTITION"
    )


def frame(flags=2, seq=100, payload=b""):
    ethernet = bytes(12) + b"\x08\x00"
    ip = bytearray(20)
    ip[0] = 0x45
    ip[9] = 6
    struct.pack_into("!H", ip, 2, 40 + len(payload))
    ip[12:16] = bytes((192, 0, 2, 1))
    ip[16:20] = bytes((192, 0, 2, 2))
    tcp = bytearray(20)
    struct.pack_into("!HHII", tcp, 0, 2000, 443, seq, 0)
    tcp[12] = 0x50
    tcp[13] = flags
    return ethernet + ip + tcp + payload


@pytest.mark.parametrize("flags", [2, 16, 17, 4, 24])
def test_reference_wire_flags_payload_and_record_identity(tmp_path, flags):
    packet = frame(flags, payload=b"fixture")
    raw = (
        struct.pack("<IHHiiII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1, 123, len(packet), len(packet))
        + packet
    )
    path = tmp_path / "fixture.pcap"
    path.write_bytes(raw)
    records, counts = read_reference(path, hashlib.sha256(raw).hexdigest())
    ref = records[1]
    assert ref.flags == flags and ref.sequence == 100 and ref.payload_length == 7
    assert (
        ref.payload_sha256 == hashlib.sha256(b"fixture").hexdigest()
        and ref.timestamp_ns == 1_000_123_000
    )
    assert counts["raw_packets"] == counts["parsed_packets"] == 1
    with pytest.raises(ValueError, match="SOURCE_DIGEST"):
        read_reference(path, "b" * 64)


@pytest.mark.parametrize("cut", [0, 10, 13, 15, 30, 40])
def test_reference_malformed_and_truncated_headers(cut):
    with pytest.raises(ValueError):
        decode_frame(1, 0, frame()[:cut], 54)


def test_duplicate_uid_elsewhere_blocks_new_promotion():
    flow, labels, wire = case()
    assert (
        recover(flow, replace(labels, counts={"duplicate_uid": 1}), wire).status
        == "AMBIGUOUS"
    )


def test_holdout_class_presence_does_not_grant_admission():
    from ml.iot23.binding_audit import review_holdout

    sessions = [
        {
            "session": "CTU-IoT-Malware-Capture-" + sid,
            "verified_classes": {"Benign": 20, "Malicious": n},
        }
        for sid, n in [("8-1", 2056), ("20-1", 4)]
    ]
    result = review_holdout(sessions)
    assert result["class_presence"] == {"train": "PASS", "validation": "PASS"}
    assert result["admission"] == "BLOCKED" and result["admitted_samples"] == 0
    sessions[1]["session"] = "CTU-IoT-Malware-Capture-34-1"
    with pytest.raises(ValueError, match="LEAKAGE"):
        review_holdout(sessions)


def test_sealed_test_requires_frozen_source_hashes():
    import json
    from pathlib import Path

    from ml.iot23.binding_audit import verify_policy_lock

    root = Path(__file__).parents[2]
    names = (
        "src/ml/iot23/recovery.py",
        "src/ml/iot23/wire_reference.py",
        "src/ml/iot23/binding_audit.py",
    )
    document = {
        "policy_digest": digest(policy()),
        "source_sha256": {
            f: hashlib.sha256((root / f).read_bytes()).hexdigest() for f in names
        },
        "test_opened_for_rule_selection": False,
    }
    document["manifest_digest"] = digest(document)
    verify_policy_lock(document)
    bad = json.loads(json.dumps(document))
    bad["source_sha256"][names[0]] = "0" * 64
    bad["manifest_digest"] = digest(
        {k: v for k, v in bad.items() if k != "manifest_digest"}
    )
    with pytest.raises(ValueError):
        verify_policy_lock(bad)
    with pytest.raises(ValueError):
        verify_policy_lock({})


def test_independent_wire_row_first_count_reference():
    from ml.iot23.wire_reference import partition_reference

    _flow, labels, wire = case()
    rows = next(iter(labels.rows.values()))
    result = partition_reference(tuple(wire.values()), rows)
    assert result["status"] == "PASS"
    assert [x["actual_counts"] for x in result["connection_counters"]] == [
        [3, 180, 0, 0],
        [1, 60, 0, 0],
        [1, 60, 0, 0],
        [1, 60, 0, 0],
    ]
    assert partition_reference(tuple(wire.values()), rows[:-1])["status"] == "FAIL"
    assert (
        partition_reference(tuple(wire.values()), rows + rows[:1])["status"] == "FAIL"
    )
