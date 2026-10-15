"""Hand-checked synthetic arithmetic tests; not operational accuracy evidence."""

import dataclasses
import hashlib
import json
import math
import struct
from pathlib import Path

import pytest

from ml.verified_producers import dns_features, network_features
from ml.verified_producers.contracts import DNS_NAMES, NETWORK_NAMES, contract, digest
from ml.verified_producers.network import Packet

FIXTURE = Path(__file__).parent / "fixtures/golden.json"
GOLDEN_SHA = "6f09de36e2e0e12ded927fa0e8fafe968b0f343a8bfb04be912de7b94ebadcf7"
CASES = json.loads(FIXTURE.read_text())["cases"]


def compute(case):
    if case["kind"] == "dns":
        return dns_features(case["fqdn"], source_origin=case["source_origin"])
    return network_features(
        tuple(Packet(**p) for p in case["packets"]),
        source_origin=case["source_origin"],
        capture_quality=case["capture_quality"],
    )


def verify_golden(blob):
    if hashlib.sha256(blob).hexdigest() != GOLDEN_SHA:
        raise ValueError("GOLDEN_IDENTITY_MISMATCH")
    for case in json.loads(blob)["cases"]:
        assert case["configuration_digest"] == digest(contract(case["kind"]))
        result = compute(case)
        for actual, expected in zip(result.values, case["expected"], strict=True):
            assert math.isclose(actual, expected, rel_tol=1e-6, abs_tol=1e-6)


def test_pinned_golden_and_hand_reference():
    verify_golden(FIXTURE.read_bytes())
    # Independent sample reference: three lengths 40,80,40; sum of squares / N - mean².
    variance = (40**2 + 80**2 + 40**2) / 3 - (160 / 3) ** 2
    assert compute(CASES[0]).values[8] == pytest.approx(math.sqrt(variance), rel=1e-6)


@pytest.mark.parametrize("case", CASES)
def test_determinism_and_float32(case):
    a, b = compute(case), compute(case)
    assert a == b and a.feature_digest == b.feature_digest
    assert all(struct.unpack("!f", struct.pack("!f", x))[0] == x for x in a.values)
    assert a.feature_names == (
        NETWORK_NAMES if case["kind"] == "network" else DNS_NAMES
    )
    assert a.source_origin.startswith("EXPLICIT_")


@pytest.mark.parametrize(
    "field,value",
    [("expected", [0]), ("configuration_digest", "0" * 64), ("origin", "NATIVE")],
)
def test_golden_tampering(field, value):
    blob = json.loads(FIXTURE.read_text())
    blob["cases"][0][field] = value
    with pytest.raises(ValueError, match="GOLDEN_IDENTITY"):
        verify_golden(json.dumps(blob).encode())


def test_configuration_and_order_identity():
    config = contract("network")
    original = digest(config)
    config["feature_names"] = list(reversed(config["feature_names"]))
    assert digest(config) != original
    config = contract("network")
    config["idle_timeout_ns"] = 1
    assert digest(config) != original
    a = compute(CASES[0])
    assert (
        dataclasses.replace(
            a, feature_names=tuple(reversed(a.feature_names))
        ).feature_digest
        != a.feature_digest
    )
    assert (
        dataclasses.replace(a, configuration_digest="0" * 64).feature_digest
        != a.feature_digest
    )
    assert (
        dataclasses.replace(a, source_digest="0" * 64).feature_digest
        != a.feature_digest
    )


@pytest.mark.parametrize(
    "value",
    [
        "",
        ".",
        "..",
        "a..b",
        "a.b..",
        " a.b",
        "a.b ",
        "한글.test",
        "é.test",
        "a" * 64 + ".b",
        "a.\\b",
        "a/b",
        None,
        float("nan"),
    ],
)
def test_dns_invalid(value):
    with pytest.raises(ValueError):
        dns_features(value, source_origin="EXPLICIT_FQDN_FIXTURE")


def test_dns_normalization_is_explicit_not_source_rewriting():
    a = dns_features("Aa.11.", source_origin="EXPLICIT_FQDN_FIXTURE")
    b = dns_features("aa.11", source_origin="EXPLICIT_FQDN_FIXTURE")
    assert a.values == b.values
    assert a.source_digest != b.source_digest and a.feature_digest != b.feature_digest
    assert dns_features("xn--p1ai.test", source_origin="EXPLICIT_FQDN_FIXTURE")
    assert dns_features("a", source_origin="EXPLICIT_FQDN_FIXTURE").values[-1] == 0


def packets():
    return tuple(Packet(**p) for p in CASES[0]["packets"])


def net(items, quality="UNKNOWN"):
    return network_features(
        items, source_origin="EXPLICIT_PACKET_FIXTURE", capture_quality=quality
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("timestamp_ns", -1),
        ("timestamp_ns", 1.0),
        ("timestamp_ns", True),
        ("ip_length", float("nan")),
        ("ip_length", 65536),
        ("ip_length", 20),
        ("tcp_flags", 512),
        ("source_port", -1),
        ("destination_port", 65536),
        ("transport", "icmp"),
        ("source_address", "not-ip"),
        ("destination_address", "::1"),
        ("event_id", ""),
    ],
)
def test_packet_validation(field, value):
    with pytest.raises(ValueError):
        dataclasses.replace(packets()[0], **{field: value})


@pytest.mark.parametrize(
    "items", [(), packets()[::-1], (packets()[0],) * 2, (packets()[0],) * 4097]
)
def test_invalid_sequence(items):
    with pytest.raises(ValueError):
        net(items)


def test_mixed_flow_and_timeout_boundaries():
    first = packets()[0]
    with pytest.raises(ValueError, match="MIXED_FLOW"):
        net((first, dataclasses.replace(packets()[1], source_port=123)))
    for t in [30_000_000_000, 120_000_000_000]:
        with pytest.raises(ValueError, match="TIMEOUT"):
            net((first, dataclasses.replace(packets()[1], timestamp_ns=t)))
    assert net((first, dataclasses.replace(packets()[1], timestamp_ns=29_999_999_999)))
    long = tuple(
        dataclasses.replace(first, event_id=str(i), timestamp_ns=i * 20_000_000_000)
        for i in range(7)
    )
    with pytest.raises(ValueError, match="TIMEOUT"):
        net(long)
    for quality in ["GAPPED", "DROPPED", "LOSS_FREE_CLAIM"]:
        with pytest.raises(ValueError, match="INCOMPLETE"):
            net(packets(), quality)


def test_singleton_ipv6_udp_and_zero_duration():
    p = Packet("v6", "a" * 64, "fixture-v6", 0, "::1", "::2", 100, 200, "udp", 48)
    result = net((p,))
    assert result.values[0] == result.values[-1] == result.values[-2] == 0
    assert result.values[9:12] == (0, 0, 0)
    assert net((p, dataclasses.replace(p, event_id="second"))).values[0] == 0
    with pytest.raises(ValueError):
        dataclasses.replace(p, tcp_flags=1)
    with pytest.raises(ValueError):
        dataclasses.replace(p, destination_address="::1", destination_port=100)


def test_producer_does_not_attest_origin_or_promote_model():
    native = network_features(
        packets(), source_origin="NATIVE_AF_PACKET", capture_quality="UNKNOWN"
    )
    assert native.quality == "UNKNOWN"
    assert not hasattr(native, "inference_permission")
    with pytest.raises(ValueError):
        dns_features("a.b", source_origin="MODEL_INFERENCE")
    with pytest.raises(ValueError):
        network_features(
            packets(), source_origin="UNVERIFIED", capture_quality="UNKNOWN"
        )


@pytest.mark.parametrize(
    "field,value", [("interface_id", "b" * 64), ("capture_session_id", "other-session")]
)
def test_cannot_merge_capture_sources(field, value):
    with pytest.raises(ValueError, match="MIXED_FLOW"):
        net((packets()[0], dataclasses.replace(packets()[1], **{field: value})))


@pytest.mark.parametrize("value", [float("inf"), float("-inf"), float("nan"), None])
def test_missing_or_nonfinite_packet_values(value):
    with pytest.raises(ValueError):
        dataclasses.replace(packets()[0], ip_length=value)


def test_exported_specification_matches_implemented_contract():
    root = Path(__file__).resolve().parents[2]
    spec = json.loads((root / "docs/verified-producer-contracts.json").read_text())
    assert spec["network"] == contract("network")
    assert spec["dns"] == contract("dns")
    assert (
        spec["model_artifact"] is None and spec["operational_gate"] == "NOT_INFERABLE"
    )


def test_evidence_pins_source_revision_and_golden_identity():
    root = Path(__file__).resolve().parents[2]
    evidence = json.loads((root / "docs/verified-producer-evidence.json").read_text())
    for name, expected in evidence["implementation_sha256"].items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected
    assert evidence["golden_sha256"] == GOLDEN_SHA
    assert evidence["new_model_artifacts"] == []
