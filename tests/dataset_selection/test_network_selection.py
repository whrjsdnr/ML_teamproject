"""Pending selection is metadata, never dataset admission or download permission."""

import copy
import json
from decimal import Decimal
from pathlib import Path

import pytest

from ml.raw_acquisition.binding import SplitRecord, validate_split
from ml.raw_acquisition.selection import verify_selection_plan
from ml.raw_acquisition.storage import DownloadSpec
from ml.verified_producers.contracts import digest
from ml.verified_producers.network import Packet
from ml.verified_producers.network_v1_1 import network_features

ROOT = Path(__file__).parents[2]


def plan():
    return json.loads((ROOT / "docs/network-training-download-plan.json").read_text())


def rehash(value):
    value["manifest_digest"] = digest(
        {k: v for k, v in value.items() if k != "manifest_digest"}
    )
    return value


def test_reviewed_plan_is_pending_and_does_not_fetch(monkeypatch):
    import urllib.request

    def denied(*args, **kwargs):
        pytest.fail("Selection validation must not open network")

    monkeypatch.setattr(urllib.request, "urlopen", denied)
    verify_selection_plan(plan())
    document = plan()
    assert document["decision"] == "ACQUISITION_READY"
    assert document["admission"] == "NOT_ADMITTED" and document["admitted_samples"] == 0
    assert len(document["shortlist"]) == 3
    assert document["model_readiness"] == {
        "Network Quality": "BLOCKED",
        "Network Edge": "BLOCKED",
    }
    # Plan verification remains pure after separately approved acquisition.
    assert document["actual_raw_bytes_downloaded"] == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("decision", "READY_FOR_RETRAINING"),
        ("admission", "ADMITTED"),
        ("download_approval", "APPROVED"),
        ("automatic_download", True),
        ("training_authority", "APPROVED"),
        ("operational_input", "READY"),
        ("write_disposition", "ALLOW"),
        ("admitted_samples", 237),
        ("verified_matches", 237),
        ("new_raw_downloads", 1),
        ("actual_raw_bytes_downloaded", 1),
        ("new_raw_decompressed_bytes", 1),
        ("overwrite_existing", True),
        ("archive_expansion_budget_bytes", 512 * 1024**2),
        ("max_files", 7),
        ("max_retries", 1),
        ("storage_directory", "/tmp/arbitrary"),
        ("dataset_digest", "a" * 64),
        ("admitted_samples", False),
    ],
)
def test_rehashed_manifest_cannot_grant_authority(field, value):
    document = plan()
    document[field] = value
    with pytest.raises(ValueError):
        verify_selection_plan(rehash(document))


@pytest.mark.parametrize(
    "kind", ["model", "producer", "golden", "holdout", "ctu", "checksum"]
)
def test_false_readiness_and_digest_are_rejected(kind):
    document = plan()
    if kind == "model":
        document["model_readiness"]["Network Edge"] = "READY_FOR_RETRAINING"
    elif kind == "producer":
        document["producer"]["configuration_digest"] = "a" * 64
    elif kind == "golden":
        document["producer"]["actual_golden_pair"] = "PASS"
    elif kind == "holdout":
        document["holdout"]["status"] = "VERIFIED"
    elif kind == "ctu":
        document["ctu13_s07_final"]["training_admission"] = "ADMITTED"
    else:
        document["expected_total_bytes"] += 1
        with pytest.raises(ValueError, match="TAMPERED"):
            verify_selection_plan(document)
        return
    with pytest.raises(ValueError):
        verify_selection_plan(rehash(document))


@pytest.mark.parametrize(
    "kind",
    [
        "url",
        "filename",
        "path",
        "bytes",
        "actual_sha",
        "duplicate",
        "missing",
        "acquired",
    ],
)
def test_wrong_file_identity_is_not_acquisition_ready(kind):
    document = plan()
    row = document["files"][0]
    if kind == "url":
        row["url"] = row["url"].replace("https://", "http://")
    elif kind == "filename":
        row["filename"] = "unreviewed.pcap"
    elif kind == "path":
        row["relative_path"] = "../escape.pcap"
    elif kind == "bytes":
        row["expected_bytes"] += 1
    elif kind == "actual_sha":
        row["actual_sha256"] = "a" * 64
    elif kind == "duplicate":
        document["files"][1] = copy.deepcopy(row)
    elif kind == "missing":
        document["files"].pop()
    else:
        row["acquired"] = True
    with pytest.raises(ValueError):
        verify_selection_plan(rehash(document))


@pytest.mark.parametrize(
    "field,value",
    [
        ("download_budget_bytes", 100),
        ("download_budget_bytes", 2**30),
        ("download_budget_bytes", True),
        ("timeout_seconds_per_file", 301),
        ("timeout_seconds_per_file", 0),
    ],
)
def test_download_budget_and_time_bound(field, value):
    document = plan()
    document[field] = value
    with pytest.raises(ValueError, match="BUDGET"):
        verify_selection_plan(rehash(document))


def test_zeek_label_transport_keeps_explicit_filename():
    row = next(f for f in plan()["files"] if f["role"] == "ZEEK_LABELED_FLOW")
    assert row["head_content_type"] == "UNKNOWN"
    spec = DownloadSpec(
        row["url"],
        row["filename"],
        row["expected_bytes"],
        row["expected_bytes"],
        ("text/plain",),
        allow_missing_content_type=True,
    )
    assert spec.filename == "conn.log.labeled"


def test_whole_session_split_and_leakage_checks():
    document = plan()
    document["holdout"]["sessions"]["test"] = document["holdout"]["sessions"]["train"]
    with pytest.raises(ValueError, match="SPLIT"):
        verify_selection_plan(rehash(document))

    def record(index, split, group):
        return SplitRecord(
            str(index) * 64,
            str(index + 2) * 64,
            str(index),
            index % 2,
            split,
            (group,),
            index * 100,
            index * 100 + 1,
        )

    with pytest.raises(ValueError, match="GROUP_LEAKAGE"):
        validate_split((record(1, "train", "capture"), record(2, "test", "capture")))


def test_epoch_utc_and_direction_feature_contract_on_explicit_fixture():
    # A Zeek-style decimal epoch needs no wall-clock/DST search. These are reserved
    # address metadata fixtures, not downloaded Zeek rows or a new golden pair.
    stamp = int(Decimal("1533042909.123456") * 10**9)
    source = "a" * 64
    first = Packet(
        "fixture:1",
        source,
        source,
        stamp,
        "192.0.2.1",
        "192.0.2.2",
        5000,
        443,
        "tcp",
        40,
        2,
    )
    second = Packet(
        "fixture:2",
        source,
        source,
        stamp + 1000,
        "192.0.2.2",
        "192.0.2.1",
        443,
        5000,
        "tcp",
        52,
        18,
    )
    result = network_features(
        (first, second), source_origin="FIXTURE", source_identity=source
    )
    assert result.feature_names[3:5] == ("forward_ip_bytes", "backward_ip_bytes")
    assert result.values[1:5] == (1.0, 1.0, 40.0, 52.0) and result.values[9] == 2.0
    assert result.configuration_digest == plan()["producer"]["configuration_digest"]
