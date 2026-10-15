"""No network: byte-level PCAP fixtures, independent arithmetic and external labels."""

import csv
import hashlib
import io
import json
import math
import struct
from dataclasses import replace
from itertools import pairwise
from pathlib import Path

import pytest

from ml.ctu13.flows import Flows
from ml.ctu13.labels import Label, LabelIndex, bind, flow_key, load_labels
from ml.ctu13.pcap import PcapReader, parse_packet
from ml.verified_producers.contracts import NETWORK_NAMES, digest
from ml.verified_producers.network import Packet
from ml.verified_producers.network import network_features as old_features
from ml.verified_producers.network_v1_1 import (
    feature_contract,
    network_features,
    producer_contract,
    verify_reference,
)

IDENTITY = "a" * 64


def packet(n=1, *, stamp=0, reverse=False, length=40, flags=2):
    endpoints = (("192.0.2.1", 1000), ("192.0.2.2", 80))
    if reverse:
        endpoints = endpoints[::-1]
    return Packet(
        str(n),
        IDENTITY,
        IDENTITY,
        stamp,
        endpoints[0][0],
        endpoints[1][0],
        endpoints[0][1],
        endpoints[1][1],
        "tcp",
        length,
        flags,
    )


def frame(*, ipv6=False, udp=False):
    ethernet = bytes(12) + (b"\x86\xdd" if ipv6 else b"\x08\x00")
    transport = bytearray(8 if udp else 20)
    struct.pack_into("!HH", transport, 0, 1000, 80)
    if udp:
        struct.pack_into("!H", transport, 4, 8)
    else:
        transport[12] = 0x50
        transport[13] = 2
    if ipv6:
        ip = bytearray(40)
        ip[0] = 0x60
        ip[6] = 17 if udp else 6
        struct.pack_into("!H", ip, 4, len(transport))
        ip[8:24] = bytes.fromhex("20010db8000000000000000000000001")
        ip[24:40] = bytes.fromhex("20010db8000000000000000000000002")
    else:
        ip = bytearray(20)
        ip[0] = 0x45
        ip[9] = 17 if udp else 6
        struct.pack_into("!H", ip, 2, len(ip) + len(transport))
        ip[12:16] = bytes([192, 0, 2, 1])
        ip[16:20] = bytes([192, 0, 2, 2])
    return ethernet + ip + transport


def pcap(data=None, *, endian="<", nano=False, wire=None):
    data = frame() if data is None else data
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    return (
        struct.pack(endian + "IHHiiII", magic, 2, 4, 0, 0, 65535, 1)
        + struct.pack(
            endian + "IIII", 1, 2, len(data), len(data) if wire is None else wire
        )
        + data
    )


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("nano", [False, True])
@pytest.mark.parametrize("ipv6", [False, True])
@pytest.mark.parametrize("udp", [False, True])
def test_pcap_formats(endian, nano, ipv6, udp):
    raw = pcap(frame(ipv6=ipv6, udp=udp), endian=endian, nano=nano)
    reader = PcapReader([raw[i : i + 7] for i in range(0, len(raw), 7)])
    records = list(reader)
    result = parse_packet(records[0], IDENTITY)
    assert result.timestamp_ns == 1_000_000_000 + 2 * (1 if nano else 1000)
    assert result.transport == ("udp" if udp else "tcp")
    assert result.ip_length == (40 if ipv6 else 20) + (8 if udp else 20)


@pytest.mark.parametrize("cut", [0, 5, 23, 30, 39, 50])
def test_truncated_pcap(cut):
    with pytest.raises(ValueError, match="TRUNCATED"):
        list(PcapReader([pcap()[:cut]]))


def test_payload_truncation_no_zero_padding():
    data = bytearray(frame())
    struct.pack_into("!H", data, 16, 1500)
    record = next(iter(PcapReader([pcap(data, wire=1514)])))
    assert parse_packet(record, IDENTITY).ip_length == 1500
    truncated = next(iter(PcapReader([pcap(bytes(data[:45]), wire=1514)])))
    with pytest.raises(ValueError, match="TRUNCATED"):
        parse_packet(truncated, IDENTITY)


@pytest.mark.parametrize(
    "offset,value,error",
    [
        (20, 0x20, "FRAGMENT"),
        (23, 1, "TRANSPORT_UNSUPPORTED"),
        (14, 0x44, "IPV4_INVALID"),
        (46, 0x10, "TCP_HEADER_INVALID"),
    ],
)
def test_bad_packet(offset, value, error):
    data = bytearray(frame())
    data[offset] = value
    record = next(iter(PcapReader([pcap(data)])))
    with pytest.raises(ValueError, match=error):
        parse_packet(record, IDENTITY)


def test_record_and_link_bounds():
    raw = bytearray(pcap())
    struct.pack_into("<I", raw, 20, 113)
    with pytest.raises(ValueError, match="HEADER_UNSUPPORTED"):
        PcapReader([raw])
    raw = bytearray(pcap())
    struct.pack_into("<I", raw, 28, 1_000_000)
    with pytest.raises(ValueError, match="RECORD_INVALID"):
        list(PcapReader([raw]))


def sample():
    return (
        packet(),
        packet(2, stamp=1_000_000_000, reverse=True, length=80, flags=18),
        packet(3, stamp=3_000_000_000, flags=1),
    )


def test_arithmetic_independent_and_v1_preserved():
    packets = sample()
    result = network_features(
        packets, source_origin="OFFLINE_PCAP", source_identity=IDENTITY
    )
    expected = (
        3,
        2,
        1,
        80,
        80,
        40,
        80,
        160 / 3,
        40 * math.sqrt(2) / 3,
        2,
        1,
        0,
        1.5,
        2,
    )
    assert result.values == tuple(
        struct.unpack("!f", struct.pack("!f", v))[0] for v in expected
    )
    legacy = old_features(
        packets, source_origin="EXPLICIT_PACKET_FIXTURE", capture_quality="UNKNOWN"
    )
    assert result.values == legacy.values and legacy.semantic_version == "1.0.0"
    with pytest.raises(ValueError, match="ORIGIN"):
        old_features(packets, source_origin="OFFLINE_PCAP", capture_quality="UNKNOWN")


@pytest.mark.parametrize("origin", ["OFFLINE_PCAP", "NATIVE_AF_PACKET", "FIXTURE"])
def test_origin_binding(origin):
    a = network_features(sample(), source_origin=origin, source_identity=IDENTITY)
    b = network_features(sample(), source_origin="FIXTURE", source_identity="b" * 64)
    assert a.source_origin == origin and a.source_digest != b.source_digest


@pytest.mark.parametrize(
    "change",
    [
        {"source_origin": "EXPLICIT_PACKET_FIXTURE"},
        {"source_identity": "bad"},
        {"capture_quality": "KNOWN_GAP"},
    ],
)
def test_invalid_origin_or_quality(change):
    kwargs = {"source_origin": "OFFLINE_PCAP", "source_identity": IDENTITY} | change
    with pytest.raises(ValueError):
        network_features(sample(), **kwargs)


@pytest.mark.parametrize(
    "packets",
    [
        (),
        (packet(), packet()),
        (packet(stamp=10), packet(2, stamp=0)),
        (packet(), packet(2, stamp=30_000_000_000)),
        (packet(), replace(packet(2), interface_id="b" * 64)),
    ],
)
def test_invalid_flow(packets):
    with pytest.raises(ValueError):
        network_features(
            packets, source_origin="OFFLINE_PCAP", source_identity=IDENTITY
        )


def reference():
    result = network_features(
        sample(), source_origin="OFFLINE_PCAP", source_identity=IDENTITY
    )
    return {
        "producer_version": "1.1.0",
        "configuration_digest": digest(producer_contract()),
        "feature_contract_digest": digest(feature_contract()),
        "source_identity": IDENTITY,
        "source_origin": "OFFLINE_PCAP",
        "source_digest": result.source_digest,
        "feature_names": list(NETWORK_NAMES),
        "values": list(result.values),
    }


@pytest.mark.parametrize(
    "field",
    [
        "producer_version",
        "configuration_digest",
        "feature_contract_digest",
        "source_identity",
        "source_origin",
        "source_digest",
        "feature_names",
        "values",
    ],
)
def test_reference_tamper(field):
    value = reference()
    verify_reference(
        sample(), value, source_identity=IDENTITY, source_origin="OFFLINE_PCAP"
    )
    value[field] = "forged"
    with pytest.raises(ValueError, match="REFERENCE_MISMATCH"):
        verify_reference(
            sample(), value, source_identity=IDENTITY, source_origin="OFFLINE_PCAP"
        )


def index(*labels, verified=True):
    return LabelIndex(
        {flow_key(packet()): tuple(labels)}, {}, verified, IDENTITY, "b" * 64
    )


def label(**changes):
    return replace(
        Label(flow_key(packet()), 0, 4_000_000_000, "NORMAL", "c" * 64, "<->"),
        **changes,
    )


@pytest.mark.parametrize(
    "labels,status",
    [
        (index(label()), "MATCHED"),
        (index(label(), verified=False), "CLOCK_UNVERIFIED"),
        (index(label(), label(classification="BOTNET")), "AMBIGUOUS"),
        (index(label(classification="UNKNOWN")), "UNKNOWN_LABEL"),
        (index(label(end_ns=1)), "UNMATCHED"),
        (index(), "UNMATCHED"),
    ],
)
def test_external_label_binding(labels, status):
    assert bind(sample(), labels)[0] == status
    assert (
        bind((replace(packet(), capture_session_id="forged"),), labels)[0]
        == "SESSION_MISMATCH"
    )


def test_direction_time_and_bounds():
    flows = Flows(max_active=2, max_buffered=5)
    assert not flows.add(packet())
    assert not flows.add(packet(2, stamp=10, reverse=True))
    closed = flows.add(packet(3, stamp=30_000_000_010))
    assert (
        len(closed) == 1
        and closed[0].closure == "IDLE_TIMEOUT"
        and len(closed[0].packets) == 2
    )
    with pytest.raises(ValueError, match="LATE"):
        flows.add(packet(4, stamp=0))
    assert flows.finish(complete=False)[0].closure == "INCOMPLETE_CAPTURE"


def test_resource_eviction_and_active_timeout():
    flows = Flows(max_active=1, max_buffered=2)
    flows.add(packet())
    assert (
        flows.add(replace(packet(2), source_port=2000))[0].closure
        == "RESOURCE_EVICTION"
    )
    flows = Flows()
    for i in range(6):
        closed = flows.add(packet(i + 1, stamp=i * 24_000_000_000))
    assert closed[0].closure == "ACTIVE_TIMEOUT"


def test_label_file_hash_and_unknown_mapping(tmp_path):
    stream = io.StringIO()
    writer = csv.DictWriter(
        stream,
        fieldnames=[
            "StartTime",
            "Dur",
            "Proto",
            "SrcAddr",
            "Sport",
            "Dir",
            "DstAddr",
            "Dport",
            "Label",
        ],
    )
    writer.writeheader()
    base = {
        "StartTime": "2011/08/16 13:51:24.000000",
        "Dur": "1.0",
        "Proto": "tcp",
        "SrcAddr": "192.0.2.1",
        "Sport": "1000",
        "Dir": "<->",
        "DstAddr": "192.0.2.2",
        "Dport": "80",
    }
    for value in [
        "flow=Background",
        "flow=To-Botnet-V48-TCP",
        "flow=From-Normal-V48-Test",
        "flow=From-Botnet-V48-TCP",
    ]:
        writer.writerow(base | {"Label": value})
    path = tmp_path / "labels.binetflow"
    path.write_text(stream.getvalue())
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    result = load_labels(
        path, label_identity=sha, session_identity=IDENTITY, utc_offset_seconds=7200
    )
    assert (
        result.counts["UNKNOWN"] == 2
        and result.counts["NORMAL"] == 1
        and result.counts["BOTNET"] == 1
    )
    with pytest.raises(ValueError, match="DIGEST"):
        load_labels(
            path,
            label_identity="0" * 64,
            session_identity=IDENTITY,
            utc_offset_seconds=0,
        )
    with pytest.raises(ValueError, match="CLOCK"):
        load_labels(
            path,
            label_identity=sha,
            session_identity=IDENTITY,
            utc_offset_seconds=999999,
        )


def test_checked_in_actual_reference():
    path = Path(__file__).parents[2] / "docs/ctu13-s07-evidence.json"
    if not path.exists():
        pytest.fail("Actual evidence summary required")
    report = json.loads(path.read_text())
    assert report["operational_inference"] == "NOT_INFERABLE"
    assert (
        report["admitted_sample_count"] == 0
        and report["retraining_readiness"] == "BLOCKED"
    )
    ref = report["reference_input"]
    if ref is not None:
        assert ref["independent_reference_status"] == "VERIFIED_ARITHMETIC_ONLY"


def ng_block(kind, body):
    length = 12 + len(body)
    return struct.pack("<II", kind, length) + body + struct.pack("<I", length)


def ng_pcap(data=None):
    data = frame() if data is None else data
    shb = ng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = ng_block(1, struct.pack("<HHI", 1, 0, 65535))
    epb = ng_block(
        6,
        struct.pack("<IIIII", 0, 0, 1_000_002, len(data), len(data))
        + data
        + bytes((-len(data)) % 4),
    )
    return shb + idb + epb


def test_pcapng_actual_format_fixture():
    reader = PcapReader([ng_pcap()])
    records = list(reader)
    assert reader.format == "PCAPNG" and records[0].timestamp_ns == 1_000_002_000
    assert parse_packet(records[0], IDENTITY).ip_length == 40


@pytest.mark.parametrize(
    "mutation", ["trailer", "interface", "size", "resolution", "section"]
)
def test_pcapng_tamper(mutation):
    raw = bytearray(ng_pcap())
    if mutation == "trailer":
        raw[-1] = 9
    elif mutation == "interface":
        struct.pack_into("<I", raw, 56, 3)
    elif mutation == "size":
        struct.pack_into("<I", raw, 52, 2**30)
    elif mutation == "section":
        raw += ng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    else:
        raw = ng_block(
            0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        ) + ng_block(1, struct.pack("<HHIHHB3x", 1, 0, 65535, 9, 1, 0x80))
    with pytest.raises(ValueError, match="PCAPNG"):
        list(PcapReader([bytes(raw)]))


def test_expansion_guard_never_decodes_over_budget(tmp_path, monkeypatch):
    import bz2

    from ml.raw_acquisition.storage import iter_bzip2

    original = bz2.BZ2Decompressor
    decoded = []

    class Observed:
        def __init__(self):
            self.inner = original()

        def __getattr__(self, name):
            return getattr(self.inner, name)

        def decompress(self, data, *, max_length):
            result = self.inner.decompress(data, max_length=max_length)
            decoded.append(len(result))
            return result

    monkeypatch.setattr(bz2, "BZ2Decompressor", Observed)
    path = tmp_path / "bounded.bz2"
    path.write_bytes(bz2.compress(bytes(101)))
    with pytest.raises(ValueError, match="EXPANSION_LIMIT"):
        list(iter_bzip2(path, max_expanded_bytes=100))
    assert sum(decoded) == 100


def test_pilot_refuses_existing_output_and_forged_receipts(tmp_path):
    from ml.ctu13.pilot import inspect

    tmp_path.chmod(0o700)
    (tmp_path / "acquisition-receipts.json").write_text("[]")
    with pytest.raises(ValueError, match="IDENTITY_MISMATCH"):
        inspect(tmp_path)
    for budget in (0, 512 * 1024**2 + 1, True):
        with pytest.raises(ValueError, match="EXPANSION_LIMIT"):
            inspect(tmp_path, expansion_budget_bytes=budget)


def test_actual_reference_independent_decimal_and_summary_integrity():
    from decimal import Decimal, localcontext

    report = json.loads(
        (Path(__file__).parents[2] / "docs/ctu13-s07-evidence.json").read_text()
    )
    expected_digest = report.pop("evidence_summary_digest")
    assert digest(report) == expected_digest
    ref = report["reference_input"]
    packets = ref["packet_metadata"]
    with localcontext() as context:
        context.prec = 60
        lengths = [Decimal(p["ip_length"]) for p in packets]
        mean = sum(lengths) / len(lengths)
        iats = [
            Decimal(b["relative_ns"] - a["relative_ns"]) / 10**9
            for a, b in pairwise(packets)
        ]
        expected = [
            Decimal(packets[-1]["relative_ns"]) / 10**9,
            sum(p["forward"] for p in packets),
            sum(not p["forward"] for p in packets),
            sum(p["ip_length"] for p in packets if p["forward"]),
            sum(p["ip_length"] for p in packets if not p["forward"]),
            min(lengths),
            max(lengths),
            mean,
            (sum((v - mean) ** 2 for v in lengths) / len(lengths)).sqrt(),
            sum(bool(p["tcp_flags"] & 2) for p in packets),
            sum(bool(p["tcp_flags"] & 1) for p in packets),
            sum(bool(p["tcp_flags"] & 4) for p in packets),
            sum(iats) / len(iats),
            max(iats),
        ]
    assert [
        struct.unpack("!f", struct.pack("!f", float(v)))[0] for v in expected
    ] == ref["values"]
    assert ref["configuration_digest"] == digest(producer_contract())
    assert ref["feature_contract_digest"] == digest(feature_contract())
    assert (
        report["dataset_admission"] == "BLOCKED"
        and report["label_clock"]["verified"] is False
    )
