import copy
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from ml.iot23.inspect import independent_reference, reference_document, verify_reference
from ml.iot23.integrity import GATES, admission, verify_acquisition, verify_manifest
from ml.iot23.zeek import (
    FIELDS,
    TYPES,
    Connection,
    Labels,
    bind,
    columns,
    epoch_ns,
    load,
)
from ml.verified_producers.contracts import digest
from ml.verified_producers.network import Packet
from ml.verified_producers.network_v1_1 import network_features

IDENTITY = "a" * 64


def packets():
    first = Packet(
        "event1",
        IDENTITY,
        IDENTITY,
        1_000_000_000,
        "192.0.2.1",
        "192.0.2.2",
        2000,
        443,
        "tcp",
        40,
        2,
    )
    second = replace(
        first,
        event_id="event2",
        timestamp_ns=2_000_000_000,
        source_address="192.0.2.2",
        destination_address="192.0.2.1",
        source_port=443,
        destination_port=2000,
        ip_length=60,
        tcp_flags=18,
    )
    return first, second


def labels():
    p = packets()[0]
    key = ("tcp", tuple(sorted(p.endpoints)))
    row = Connection(
        "ref",
        "uid",
        IDENTITY,
        key,
        p.endpoints[0],
        1_000_000_000,
        2_000_000_000,
        "Malicious",
        "C&C",
        (1, 40, 1, 60),
        0,
    )
    return Labels({key: (row,)}, {}, "schema", "b" * 64, IDENTITY)


def modified(**kwargs):
    data = labels()
    key = next(iter(data.rows))
    return replace(data, rows={key: (replace(data.rows[key][0], **kwargs),)})


def test_binding_exact_epoch_direction_and_independent_arithmetic():
    assert bind(packets(), labels())[0] == "VERIFIED_MATCH"
    vector = network_features(
        packets(), source_origin="OFFLINE_PCAP", source_identity=IDENTITY
    )
    assert vector.values == independent_reference(packets())
    assert vector.values == (
        1.0,
        1.0,
        1.0,
        40.0,
        60.0,
        40.0,
        60.0,
        50.0,
        10.0,
        2.0,
        0.0,
        0.0,
        1.0,
        1.0,
    )
    doc = reference_document(packets(), IDENTITY)
    verify_reference(packets(), doc, IDENTITY)
    native = network_features(
        packets(), source_origin="NATIVE_AF_PACKET", source_identity=IDENTITY
    )
    assert (
        native.values == vector.values and native.source_digest != vector.source_digest
    )
    assert (
        doc["training_native_parity"] == "NOT_VERIFIED"
    )  # Declared metadata parity is not native capture parity.


@pytest.mark.parametrize(
    "change,status",
    [
        ({"label": "Background"}, "EXCLUDED"),
        ({"label": "Unknown"}, "EXCLUDED"),
        ({"label": "-"}, "EXCLUDED"),
        ({"end_ns": None}, "EXCLUDED"),
        ({"start_ns": 1_000_000_001}, "UNMATCHED"),
        ({"counts": (2, 80, 1, 60)}, "CANDIDATE_MATCH"),
        ({"counts": None}, "EXCLUDED"),
        ({"missed_bytes": 1}, "EXCLUDED"),
        ({"missed_bytes": None}, "EXCLUDED"),
        ({"orig": ("192.0.2.2", 443), "counts": (1, 60, 1, 40)}, "VERIFIED_MATCH"),
    ],
)
def test_binding_uncertainty_no_imputation(change, status):
    assert bind(packets(), modified(**change))[0] == status


def test_ambiguous_duplicate_label_session_forgery():
    data = labels()
    key = next(iter(data.rows))
    duplicate = replace(data, rows={key: data.rows[key] * 2})
    assert bind(packets(), duplicate)[0] == "AMBIGUOUS"
    assert bind(packets(), replace(data, session="forged"))[0] == "EXCLUDED"
    assert bind(packets()[::-1], data)[0] == "EXCLUDED"
    assert (
        bind((replace(packets()[0], source_port=22), packets()[1]), data)[0]
        == "EXCLUDED"
    )


@pytest.mark.parametrize(
    "field",
    [
        "source_identity",
        "source_origin",
        "configuration_digest",
        "feature_names",
        "expected_values",
        "packet_metadata_digest",
    ],
)
def test_reference_tampering(field):
    doc = reference_document(packets(), IDENTITY)
    doc[field] = "forged"
    with pytest.raises(ValueError, match="REFERENCE"):
        verify_reference(packets(), doc, IDENTITY)


def label_text(alias="detailed-label", triple=True):
    fields = FIELDS[:-1] + (alias,)
    values = (
        "1.000000",
        "uid",
        "192.0.2.1",
        "2000",
        "192.0.2.2",
        "443",
        "tcp",
        "-",
        "1.000000",
        "0",
        "0",
        "SF",
        "-",
        "-",
        "0",
        "Sh",
        "1",
        "40",
        "1",
        "60",
        "-",
        "Malicious",
        "C&C",
    )

    def join(cells):
        return (
            "\t".join(cells[:20]) + "\t" + "   ".join(cells[20:])
            if triple
            else "\t".join(cells)
        )

    return (
        "#separator \\x09\n#fields\t"
        + join(fields)
        + "\n#types\t"
        + join(TYPES)
        + "\n"
        + join(values)
        + "\n"
    )


@pytest.mark.parametrize(
    "alias,triple", [("detailed-label", True), ("det_label", False)]
)
def test_observed_zeek_schema_aliases(tmp_path, alias, triple):
    path = tmp_path / "labels"
    path.write_text(label_text(alias, triple))
    result = load(path, hashlib.sha256(path.read_bytes()).hexdigest(), IDENTITY)
    assert result.counts["total_rows"] == 1
    assert bind(packets(), result)[0] == "VERIFIED_MATCH"
    path.write_text(path.read_text() + "tamper")
    with pytest.raises(ValueError, match="DIGEST"):
        load(path, "b" * 64, IDENTITY)


@pytest.mark.parametrize(
    "change",
    [
        lambda s: s.replace("id.orig_h", "bad"),
        lambda s: s.replace("#types\ttime", "#types\tstring"),
        lambda s: s.replace("#separator \\x09", "#separator space"),
        lambda s: s.replace("Malicious", ""),
    ],
)
def test_invalid_header_or_missing_label_fail_closed(tmp_path, change):
    path = tmp_path / "labels"
    path.write_text(change(label_text()))
    with pytest.raises(ValueError):
        load(path, hashlib.sha256(path.read_bytes()).hexdigest(), IDENTITY)


@pytest.mark.parametrize("value", ["NaN", "Infinity", "-1", "0.0000000001", "1e40"])
def test_epoch_invalid(value):
    with pytest.raises(ValueError):
        epoch_ns(value)


def test_epoch_does_not_guess_timezone_or_dst():
    assert epoch_ns("1533042911.474174") == 1533042911474174000
    assert columns("\t".join(FIELDS)) == FIELDS


@pytest.mark.parametrize("gate", GATES)
def test_admission_each_missing_gate_blocks(gate):
    gates = dict.fromkeys(GATES, "PASS")
    gates[gate] = "UNKNOWN"
    assert admission(gates) == "BLOCKED"
    assert admission({}) == "BLOCKED"


def test_manifest_tampering_and_rehashed_bypass():
    doc = {
        "admission": "BLOCKED",
        "gates": dict.fromkeys(GATES, "UNKNOWN"),
        "operational_input": "NOT_INFERABLE",
        "write_disposition": "WRITE_DENIED",
    }
    doc["manifest_digest"] = digest(doc)
    verify_manifest(doc)
    bad = copy.deepcopy(doc)
    bad["admission"] = "READY_FOR_RETRAINING"
    with pytest.raises(ValueError, match="TAMPERED"):
        verify_manifest(bad)
    bad["manifest_digest"] = digest(
        {k: v for k, v in bad.items() if k != "manifest_digest"}
    )
    with pytest.raises(ValueError, match="GATE"):
        verify_manifest(bad)
    bad.update(gates=dict.fromkeys(GATES, "PASS"))
    bad["manifest_digest"] = digest(
        {k: v for k, v in bad.items() if k != "manifest_digest"}
    )
    with pytest.raises(ValueError):
        verify_manifest(bad)


def test_exact_source_plan_identity():
    import json

    plan = json.loads(
        (
            Path(__file__).parents[2] / "docs/network-training-download-plan.json"
        ).read_text()
    )
    rows = [
        {
            **r,
            "size_bytes": r["expected_bytes"],
            "sha256": "a" * 64,
            "http_status": 200,
            "publisher_digest_verified": False,
        }
        for r in plan["files"]
    ]
    document = {
        "status": "DOWNLOADED_NOT_ADMITTED",
        "actual_total_bytes": 137251065,
        "archive_expansion_bytes": 0,
        "download_budget_bytes": 268435456,
        "files": rows,
    }
    verify_acquisition(document, plan)
    for key, value in [
        ("relative_path", "../outside"),
        ("url", "https://bad.invalid"),
        ("size_bytes", 1),
        ("publisher_digest_verified", True),
    ]:
        bad = copy.deepcopy(document)
        bad["files"][0][key] = value
        with pytest.raises(ValueError):
            verify_acquisition(bad, plan)


def test_trailing_tcp_packet_not_given_label_by_duration_extension():
    result = bind(packets(), modified(end_ns=1_999_999_000))
    assert (
        result[0] == "CANDIDATE_MATCH"
        and result[2] == "ZEEK_DURATION_DOES_NOT_CONTAIN_ALL_PACKETS"
    )


def test_conflicting_labels_never_arbitrarily_selected():
    data = labels()
    key = next(iter(data.rows))
    row = data.rows[key][0]
    changed = replace(
        data, rows={key: (row, replace(row, label="Benign", reference="different"))}
    )
    assert bind(packets(), changed)[0] == "AMBIGUOUS"


def test_label_row_session_binding_cannot_be_forged():
    assert bind(packets(), modified(session="other-session"))[0] == "EXCLUDED"
