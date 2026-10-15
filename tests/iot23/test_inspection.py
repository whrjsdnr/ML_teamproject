"""Actual byte parser → flow → label → producer; these inputs are fixtures."""

import hashlib
import struct
from pathlib import Path

import pytest

from ml.iot23.inspect import inspect_session
from ml.iot23.zeek import FIELDS, TYPES


def fixtures(tmp_path: Path, *, missing_duration=False):
    ethernet = bytes(12) + b"\x08\x00"
    ip = bytearray(20)
    ip[0] = 0x45
    ip[9] = 6
    struct.pack_into("!H", ip, 2, 40)
    ip[12:16] = bytes((192, 0, 2, 1))
    ip[16:20] = bytes((192, 0, 2, 2))
    tcp = bytearray(20)
    struct.pack_into("!HH", tcp, 0, 2000, 443)
    tcp[12] = 0x50
    tcp[13] = 2
    frame = ethernet + ip + tcp
    raw = struct.pack("<IHHiiII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for seconds in (1, 2):
        raw += struct.pack("<IIII", seconds, 0, len(frame), len(frame)) + frame
    path = tmp_path / "fixture.pcap"
    path.write_bytes(raw)
    values = (
        "1.000000",
        "uid",
        "192.0.2.1",
        "2000",
        "192.0.2.2",
        "443",
        "tcp",
        "-",
        "-" if missing_duration else "1.000000",
        "0",
        "0",
        "S0",
        "-",
        "-",
        "0",
        "S",
        "2",
        "80",
        "0",
        "0",
        "-",
        "Malicious",
        "C&C",
    )
    text = (
        "#separator \\x09\n#fields\t"
        + "\t".join(FIELDS)
        + "\n#types\t"
        + "\t".join(TYPES)
        + "\n"
        + "\t".join(values)
        + "\n"
    )
    label = tmp_path / "conn.log.labeled"
    label.write_text(text)
    return {
        "relative_path": path.name,
        "capture_session": "EXPLICIT_FIXTURE",
        "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }, {
        "relative_path": label.name,
        "sha256": hashlib.sha256(label.read_bytes()).hexdigest(),
    }


def test_fixture_full_pipeline_is_reproducible_not_native_parity(tmp_path):
    raw, label = fixtures(tmp_path)
    report, rows = inspect_session(tmp_path, raw, label)
    second_report, second_rows = inspect_session(tmp_path, raw, label)
    assert (report, rows) == (second_report, second_rows)
    assert report["binding_status"] == {
        "VERIFIED_MATCH": 1,
        "CANDIDATE_MATCH": 0,
        "AMBIGUOUS": 0,
        "UNMATCHED": 0,
        "EXCLUDED": 0,
    }
    assert report["counts"]["parsed_packets"] == report["counts"]["raw_packets"] == 2
    assert report["pcap"]["sha256_during_full_stream"] == raw["sha256"]
    assert report["training_operational_parity"] == "NOT_VERIFIED"
    assert report["admitted_samples"] == 0 and report["capture_drop_count"] == "UNKNOWN"
    assert rows[0]["values"] == [
        1.0,
        2.0,
        0.0,
        80.0,
        0.0,
        40.0,
        40.0,
        40.0,
        0.0,
        2.0,
        0.0,
        0.0,
        1.0,
        1.0,
    ]


def test_unknown_duration_not_filled_as_zero(tmp_path):
    raw, label = fixtures(tmp_path, missing_duration=True)
    report, rows = inspect_session(tmp_path, raw, label)
    assert report["binding_status"]["VERIFIED_MATCH"] == 0
    assert rows[0]["values"] is None


def test_raw_file_digest_tampering(tmp_path):
    raw, label = fixtures(tmp_path)
    path = tmp_path / raw["relative_path"]
    path.write_bytes(path.read_bytes()[:-1] + b"X")
    with pytest.raises(ValueError, match="RAW_DIGEST"):
        inspect_session(tmp_path, raw, label)
