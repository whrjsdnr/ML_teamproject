"""Pending acquisition evidence cannot mint admission or training permission."""

import hashlib

import pytest

from ml.raw_acquisition.manifest import (
    AcquisitionCandidate,
    pending_manifest,
    verify_local_file,
    verify_manifest,
)
from ml.verified_producers.contracts import digest


def candidate(files=True):
    return AcquisitionCandidate(
        "fixture-corpus",
        "https://example.test/metadata",
        "v1",
        "fixture-terms",
        ("raw-file",),
        ("label-file",),
        files,
        True,
        ("SYNTHETIC_TEST_DECLARATION",),
    )


def test_official_listing_is_not_admitted_bytes():
    document = pending_manifest(candidate(), "dns")
    verify_manifest(document)
    assert document["acquisition_state"] == "ACQUISITION_READY"
    assert (
        document["admission"] == "NOT_ADMITTED" and document["readiness"] == "BLOCKED"
    )
    assert document["raw_sha256"] == document["sample_count"] == "UNKNOWN"
    assert (
        pending_manifest(candidate(False), "network")["acquisition_state"]
        == "INSUFFICIENT_EVIDENCE"
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("admission", "ADMITTED"),
        ("write_disposition", "WRITE_ALLOWED"),
        ("readiness", "READY_FOR_RETRAINING"),
        ("producer_version", "1.1.0"),
        ("raw_sha256", "a" * 64),
        ("sample_count", 1),
        ("operational_input", "READY"),
        ("actual_training_authority", "GRANTED"),
        ("producer_config_digest", "b" * 64),
    ],
)
def test_manifest_tamper_and_even_rehashed_promotion(field, value):
    document = pending_manifest(candidate(), "dns")
    document[field] = value
    with pytest.raises(ValueError):
        verify_manifest(document)
    body = {k: v for k, v in document.items() if k != "manifest_digest"}
    document["manifest_digest"] = digest(body)
    with pytest.raises(ValueError):
        verify_manifest(document)


def test_local_source_reverification_and_missing_file(tmp_path):
    path = tmp_path / "fixture.txt"
    path.write_bytes(b"fixture-only")
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    assert verify_local_file(path, sha, 100) == 12
    path.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="TAMPERING"):
        verify_local_file(path, sha, 100)
    with pytest.raises(FileNotFoundError):
        verify_local_file(tmp_path / "absent", sha, 100)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        verify_local_file(link, sha, 100)


def test_checked_in_pending_manifests_are_not_training_authority():
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    catalog = json.loads((root / "docs/raw-dataset-manifests.json").read_text())
    for entry in catalog["manifests"]:
        verify_manifest(entry)
    assert len(catalog["fallback_shortlist"]) == 3
    assert catalog["new_raw_downloads"] == 0
    assert catalog["model_readiness"] == {
        "network-quality": "BLOCKED",
        "network-edge": "BLOCKED",
        "dns": "BLOCKED",
    }
