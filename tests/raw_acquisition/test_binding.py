"""Synthetic binding/leakage cases, not verified public labels."""

from dataclasses import replace

import pytest

from ml.raw_acquisition.binding import (
    DomainLabel,
    NetworkLabel,
    SplitRecord,
    bind_dns,
    bind_network,
    validate_split,
)
from ml.verified_producers.contracts import digest
from ml.verified_producers.network import Packet


def packets():
    return (
        Packet(
            "test-event",
            "a" * 64,
            "fixture-session",
            100,
            "192.0.2.1",
            "192.0.2.2",
            100,
            200,
            "tcp",
            40,
        ),
    )


def label():
    return NetworkLabel(
        "fixture-session",
        "192.0.2.1",
        "192.0.2.2",
        100,
        200,
        "tcp",
        0,
        200,
        1,
        "independent-fixture-row-1",
    )


def bind(p, labels):
    return bind_network(p, labels, source_origin="EXPLICIT_PACKET_FIXTURE")


def test_explicit_fixture_binding_and_bidirectional_pair():
    assert bind(packets(), (label(),)) == label().reference
    reversed_label = replace(
        label(),
        source_address="192.0.2.2",
        destination_address="192.0.2.1",
        source_port=200,
        destination_port=100,
    )
    assert bind(packets(), (reversed_label,)) == label().reference


def test_public_pcap_is_not_relabelled_fixture_or_af_packet():
    with pytest.raises(ValueError, match="UNKNOWN_SOURCE_ORIGIN"):
        bind_network(packets(), (label(),), source_origin="OFFLINE_PCAP")


@pytest.mark.parametrize(
    "change",
    [
        {"session": "other"},
        {"start_ns": 101},
        {"end_ns": 99},
        {"source_port": 101},
        {"transport": "udp"},
        {"label": None},
        {"reference": ""},
    ],
)
def test_unmatched_and_unknown_network_labels(change):
    with pytest.raises(ValueError):
        bind(packets(), (replace(label(), **change),))


def test_ambiguous_labels_excluded_even_same_class():
    with pytest.raises(ValueError, match="AMBIGUOUS"):
        bind(packets(), (label(), label()))
    with pytest.raises(ValueError, match="AMBIGUOUS"):
        bind(packets(), (label(), replace(label(), label=0)))


def test_dns_exact_normalized_name_binding():
    label = DomainLabel(
        "Example.TEST.", 1, "fixture-label-row", "independent-fixture-source"
    )
    assert bind_dns("example.test", (label,)) == label.reference
    assert bind_dns("EXAMPLE.TEST.", (label,)) == label.reference
    for labels in [
        (),
        (label, replace(label, label=0)),
        (label, label),
        (replace(label, label=None),),
    ]:
        with pytest.raises(ValueError):
            bind_dns("example.test", labels)


def records():
    return tuple(
        SplitRecord(
            digest({"raw": i}),
            digest({"feature": i}),
            str(i),
            i % 2,
            split,
            (f"dataset:session:{i}",),
            i * 1000,
            i * 1000 + 100,
        )
        for i, split in enumerate(
            ("train", "train", "validation", "validation", "test", "test")
        )
    )


def test_frozen_group_time_split_digest_is_reproducible():
    assert validate_split(records()) == validate_split(records()[::-1])


@pytest.mark.parametrize(
    "change",
    [
        {"groups": ("dataset:session:0",)},
        {"start_ns": 0},
        {"sample_digest": digest({"raw": 0})},
        {"feature_digest": digest({"feature": 0})},
        {"groups": ()},
        {"label_reference": ""},
        {"sample_digest": "forged"},
        {"label": True},
    ],
)
def test_split_leakage_or_missing_identity(change):
    data = list(records())
    data[-1] = replace(data[-1], **change)
    with pytest.raises(ValueError):
        validate_split(tuple(data))


def test_holdout_missing_and_boundary_overlap():
    with pytest.raises(ValueError):
        validate_split(records()[:4])
    data = list(records())
    data[2] = replace(data[2], start_ns=data[1].end_ns)
    with pytest.raises(ValueError, match="TEMPORAL"):
        validate_split(tuple(data))
