"""Fixture-only lifecycle, binding and restart validation; no raw decompression."""

import hashlib
import importlib.util
import json
import subprocess
import sys
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from ml.ctu13.admission import review_binding
from ml.ctu13.flows import Flow, Flows
from ml.ctu13.labels import Label, LabelIndex, flow_key
from ml.verified_producers.contracts import digest
from ml.verified_producers.network import Packet
from ml.verified_producers.network_v1_1 import (
    feature_contract,
    network_features,
    producer_contract,
)

ROOT = Path(__file__).parents[2]
IDENTITY = "a" * 64


def packet(n=0, *, stamp=None, reverse=False, port=1000, flags=2):
    a, b = ("192.0.2.1", port), ("198.51.100.1", 80)
    if reverse:
        a, b = b, a
    return Packet(
        f"fixture:{n}",
        IDENTITY,
        IDENTITY,
        n if stamp is None else stamp,
        a[0],
        b[0],
        a[1],
        b[1],
        "tcp",
        40 + n % 30,
        flags,
    )


def baseline():
    path = ROOT / "benchmarks/fixtures/flows_8567c62.py"
    spec = importlib.util.spec_from_file_location("stream_baseline_fixture", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.Flows


@pytest.mark.parametrize(
    "mode", ["ordinary", "idle", "active", "evict", "packet_limit"]
)
def test_baseline_candidate_exact_packets_and_features(mode):
    if mode == "ordinary":
        data = [
            packet(i, reverse=bool(i % 2), flags=256 if i % 2 else 511)
            for i in range(100)
        ]
    elif mode == "idle":
        data = [packet(), packet(1, stamp=30_000_000_000)]
    elif mode == "active":
        data = [packet(i, stamp=i * 24_000_000_000) for i in range(6)]
    elif mode == "evict":
        data = [packet(i, port=1000 + i) for i in range(10)]
    else:
        data = [packet(i) for i in range(4097)]
    results = []
    for cls in (baseline(), Flows):
        table = cls(max_active=2 if mode == "evict" else 20000)
        output = []
        for p in data:
            output.extend(table.add(p))
        output.extend(table.finish(complete=True))
        results.append(
            [
                (
                    f.closure,
                    [asdict(p) for p in f.packets],
                    network_features(
                        f.packets, source_origin="FIXTURE", source_identity=IDENTITY
                    ).feature_digest,
                )
                for f in output
            ]
        )
    assert results[0] == results[1]


@pytest.mark.parametrize(
    "boundary,closure",
    [
        (29_999_999_999, None),
        (30_000_000_000, "IDLE_TIMEOUT"),
        (30_000_000_001, "IDLE_TIMEOUT"),
    ],
)
def test_idle_boundary(boundary, closure):
    table = Flows()
    table.add(packet())
    result = table.add(packet(1, stamp=boundary))
    assert (result[0].closure if result else None) == closure


@pytest.mark.parametrize(
    "kwargs,reason",
    [
        ({"max_active": 1}, "MAX_ACTIVE_FLOWS"),
        ({"max_buffered": 1}, "MAX_BUFFERED_PACKETS"),
        ({"max_state_bytes": 8192}, "STATE_BYTE_BUDGET"),
    ],
)
def test_deterministic_eviction_reasons(kwargs, reason):
    signatures = []
    for _ in range(2):
        table = Flows(**kwargs)
        outputs = []
        for i in range(8):
            outputs.extend(table.add(packet(i, port=1000 + i)))
            assert (
                table.state_bytes <= table.max_state_bytes
                and table.buffered <= table.max_buffered
            )
        assert table.peak_state_bytes <= table.max_state_bytes
        assert outputs and outputs[0].reason == reason and outputs[0].incomplete
        signatures.append([(f.flow_id, f.closure, f.reason) for f in outputs])
        assert signatures[0][0][0] == Flow((packet(),), "RESOURCE_EVICTION").flow_id
        table.finish(complete=False)
        assert table.state_bytes == table.buffered == 0
    assert signatures[0] == signatures[1]


def test_gap_completeness_and_duplicate_active_event():
    table = Flows()
    table.add(packet())
    with pytest.raises(ValueError, match="DUPLICATE"):
        table.add(packet())
    assert table.buffered == 1
    gap = table.mark_gap()
    assert gap[0].closure == "CAPTURE_GAP" and gap[0].incomplete and table.buffered == 0
    table.add(packet(1))
    assert table.finish(complete=False)[0].closure == "INCOMPLETE_CAPTURE"
    assert not table.finish(complete=True)


@pytest.mark.parametrize(
    "change", [{"interface_id": "b" * 64}, {"capture_session_id": "other"}]
)
def test_identity_rejected_even_after_idle_or_gap(change):
    table = Flows()
    table.add(packet())
    table.mark_gap()
    with pytest.raises(ValueError, match="IDENTITY"):
        table.add(replace(packet(1, stamp=60_000_000_000), **change))
    assert table.buffered == 0


def test_late_and_bad_limits():
    table = Flows()
    table.add(packet(2))
    with pytest.raises(ValueError, match="LATE"):
        table.add(packet())
    assert table.buffered == 1
    for kwargs in (
        {"max_active": True},
        {"max_buffered": 0},
        {"max_state_bytes": 1},
        {"max_state_bytes": 2**30},
    ):
        with pytest.raises(ValueError, match="LIMIT"):
            Flows(**kwargs)


def labels(*values, clock=True):
    return LabelIndex(
        {flow_key(packet()): tuple(values)}, {}, clock, IDENTITY, "b" * 64
    )


def label(**changes):
    return replace(
        Label(flow_key(packet()), 0, 10, "NORMAL", "c" * 64, "<->"), **changes
    )


@pytest.mark.parametrize(
    "index,expected",
    [
        (labels(label()), "CANDIDATE_MATCH"),
        (labels(label(), clock=False), "CANDIDATE_MATCH"),
        (labels(label(), label()), "AMBIGUOUS"),
        (labels(label(), label(classification="BOTNET")), "AMBIGUOUS"),
        (labels(), "UNMATCHED"),
        (labels(label(classification="UNKNOWN")), "EXCLUDED"),
        (labels(label(direction="forged")), "EXCLUDED"),
    ],
)
def test_review_never_trusts_caller_clock_bool(index, expected):
    result = review_binding(
        Flow((packet(), packet(1, reverse=True)), "IDLE_TIMEOUT"),
        index,
        source_origin="FIXTURE",
        source_identity=IDENTITY,
    )
    assert result.status == expected and result.status != "VERIFIED_MATCH"


def test_incomplete_and_source_forgery():
    for reason in (
        "CAPTURE_GAP",
        "RESOURCE_EVICTION",
        "PACKET_LIMIT",
        "INCOMPLETE_CAPTURE",
    ):
        assert (
            review_binding(
                Flow((packet(),), reason),
                labels(label()),
                source_origin="FIXTURE",
                source_identity=IDENTITY,
            ).status
            == "EXCLUDED"
        )
    assert (
        review_binding(
            Flow((packet(),), "IDLE_TIMEOUT"),
            labels(label()),
            source_origin="forged",
            source_identity=IDENTITY,
        ).status
        == "EXCLUDED"
    )


def test_contracts_and_baseline_fixture_are_pinned():
    assert (
        digest(producer_contract())
        == "7999723911ce3d2e9cd3b3b6e0d45e11f44b1316cdf9c7f4883d7e2a69ca21a7"
    )
    assert (
        digest(feature_contract())
        == "84ba0916f0ce4e9e12bb70712db2cd1eaea84ba4173acd57b647faf38efb1c6e"
    )
    from ml.verified_producers.contracts import contract

    assert (
        digest(contract("network"))
        == "fda9b1f4dc860de50d68401468f0e4eef6d117f57a6c06d1fd88b0ebf4059ac0"
    )
    benchmark = (ROOT / "benchmarks/ctu13_flow_benchmark.py").read_text()
    assert (
        hashlib.sha256(
            (ROOT / "benchmarks/fixtures/flows_8567c62.py").read_bytes()
        ).hexdigest()
        in benchmark
    )


def test_crash_and_restart_from_immutable_fixture(tmp_path):
    code = """import os,json
from ml.ctu13.flows import Flows
from ml.verified_producers.network import Packet
p=Packet('id','a'*64,'a'*64,0,'192.0.2.1','192.0.2.2',1,2,'udp',28,0)
f=Flows();f.add(p)
if os.environ.get('FIXTURE_CRASH')=='1': os._exit(79)
print(f.finish(complete=True)[0].flow_id)
"""
    import os

    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), FIXTURE_CRASH="1")
    crashed = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert crashed.returncode == 79 and not crashed.stdout
    env.pop("FIXTURE_CRASH")
    results = [
        subprocess.run(
            [sys.executable, "-c", code],
            env=env,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        for _ in range(2)
    ]
    assert results[0] == results[1]
    # Existing pilot consumer uses stable flow digests as duplicate receipt keys.
    seen = {results[0]}
    assert results[1] in seen
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("resolution", [6, 9])
def test_pcapng_clock_resolution_without_raw_input(endian, resolution):
    import struct

    from ml.ctu13.pcap import PcapReader

    def block(kind, body):
        size = 12 + len(body)
        return (
            struct.pack(endian + "II", kind, size)
            + body
            + struct.pack(endian + "I", size)
        )

    shb = block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack(endian + "HHIHHB3x", 1, 0, 65535, 9, 1, resolution))
    data = bytes(54)
    epb = block(
        6,
        struct.pack(endian + "IIIII", 0, 0, 123456, len(data), len(data))
        + data
        + bytes(2),
    )
    reader = PcapReader([shb + idb + epb])
    records = list(reader)
    assert records[0].timestamp_ns == 123456 * 10 ** (9 - resolution)
    assert reader.reader.bytes_read == len(shb + idb + epb)


def test_admission_rejects_forged_saved_summary(tmp_path):
    from ml.ctu13.admission import inspect_saved

    report = tmp_path / "evidence.json"
    report.write_text(
        json.dumps(
            {"evidence_summary_digest": "0" * 64, "dataset_admission": "ADMITTED"}
        )
    )
    with pytest.raises(ValueError, match="EVIDENCE_DIGEST"):
        inspect_saved(tmp_path, report)


def test_real_recheck_summary_remains_blocked():
    report = json.loads((ROOT / "docs/ctu13-s07-streaming-evidence.json").read_text())
    saved = report["saved_data_recheck"]
    assert (
        saved["new_decompressed_bytes"] == 0
        and saved["verified_matches"] == saved["admitted_samples"] == 0
    )
    assert (
        saved["admission"] == "BLOCKED"
        and saved["inference"] == "NOT_INFERABLE"
        and saved["write"] == "WRITE_DENIED"
    )
    a, b = (
        report["fixture_benchmark"]["baseline"],
        report["fixture_benchmark"]["candidate"],
    )
    assert (
        a["input_digest"] == b["input_digest"]
        and a["output_digest"] == b["output_digest"]
    )
    assert a["closure_reasons"] == b["closure_reasons"]


@pytest.mark.parametrize("kind", ["key", "reference", "source_identity"])
def test_forged_source_or_label_reference(kind):
    value = label()
    if kind == "key":
        value = replace(value, key=("udp", ()))
    if kind == "reference":
        value = replace(value, reference="forged")
    result = review_binding(
        Flow((packet(),), "IDLE_TIMEOUT"),
        labels(value),
        source_origin="OFFLINE_PCAP",
        source_identity="b" * 64 if kind == "source_identity" else IDENTITY,
    )
    assert result.status == "EXCLUDED"
