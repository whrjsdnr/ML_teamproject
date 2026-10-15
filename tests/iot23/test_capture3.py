import copy
import json
from pathlib import Path

import pytest

from ml.iot23.capture3_acquire import acquire, verify_plan
from ml.verified_producers.contracts import digest


def plan():
    return json.loads(
        (
            Path(__file__).parents[2] / "docs/iot23-capture3-download-plan.json"
        ).read_text()
    )


def rehash(document):
    document["manifest_digest"] = digest(
        {k: v for k, v in document.items() if k != "manifest_digest"}
    )
    return document


def test_approved_exact_files_and_pure_verification(monkeypatch):
    import urllib.request

    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *a: pytest.fail("No query may initiate download"),
    )
    document = plan()
    verify_plan(document)
    assert (
        len(document["files"]) == 2
        and sum(r["expected_bytes"] for r in document["files"]) == 82303309
    )


@pytest.mark.parametrize(
    "key,value",
    [
        ("download_budget_bytes", 2**30),
        ("download_budget_bytes", 1),
        ("timeout_seconds_per_file", 301),
        ("max_retries", 1),
        ("archive_expansion_bytes", 1),
        ("max_files", 3),
        ("storage_directory", "/tmp/other"),
        ("training_authority", "ALLOW"),
        ("operational_input", "READY"),
    ],
)
def test_rehashed_scope_forgery_rejected(key, value):
    document = plan()
    document[key] = value
    with pytest.raises(ValueError):
        verify_plan(rehash(document))


@pytest.mark.parametrize(
    "key,value",
    [
        ("url", "https://bad.invalid"),
        ("relative_path", "../outside"),
        ("expected_bytes", 42),
        ("filename", "test.pcap"),
    ],
)
def test_file_identity_and_path_rejected(key, value):
    document = plan()
    document["files"][0][key] = value
    with pytest.raises(ValueError):
        verify_plan(rehash(document))


def test_no_clobber_no_duplicate_transfer(tmp_path, monkeypatch):
    document = plan()
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs/iot23-capture3-download-plan.json").write_text(
        json.dumps(document)
    )
    (tmp_path / document["storage_directory"]).mkdir(parents=True)
    import ml.iot23.capture3_acquire as module

    monkeypatch.setattr(
        module, "bounded_transfer", lambda *a: pytest.fail("No duplicate transfer")
    )
    with pytest.raises(FileExistsError, match="NO_RETRY"):
        acquire(tmp_path)


def test_plan_manifest_digest():
    document = copy.deepcopy(plan())
    document["expected_total_bytes"] += 1
    with pytest.raises(ValueError, match="TAMPERED"):
        verify_plan(document)


def test_capture3_receipt_identity_integrity():
    from ml.iot23.capture3_acquire import verify_receipt

    document = plan()
    receipt = {
        "status": "DOWNLOADED_NOT_ADMITTED",
        "actual_total_bytes": 82303309,
        "archive_expansion_bytes": 0,
        "plan_digest": document["manifest_digest"],
        "files": [
            {
                **r,
                "size_bytes": r["expected_bytes"],
                "sha256": "a" * 64,
                "publisher_digest_verified": False,
            }
            for r in document["files"]
        ],
    }
    verify_receipt(receipt, document)
    for key, value in [
        ("relative_path", "../outside"),
        ("url", "https://bad.invalid"),
        ("sha256", "tampered"),
        ("size_bytes", 1),
        ("publisher_digest_verified", True),
    ]:
        bad = copy.deepcopy(receipt)
        bad["files"][0][key] = value
        with pytest.raises(ValueError):
            verify_receipt(bad, document)


def test_independence_not_implied_by_class_coverage_or_no_shared_ip():
    from ml.iot23.capture3_validate import holdout_review

    train = {
        "session": "CTU-IoT-Malware-Capture-8-1",
        "verified_classes": {"Benign": 20, "Malicious": 30},
    }
    candidate = {
        "session": "CTU-IoT-Malware-Capture-3-1",
        "verified_classes": {"Benign": 30, "Malicious": 40},
    }
    result = holdout_review(
        train,
        candidate,
        train_range=[100, 200],
        candidate_range=[10, 20],
        origin_overlap=0,
        exact_duplicates=0,
    )
    assert set(result["class_presence"].values()) == {"PASS"}
    assert result["time_overlap"] == "PASS_NO_OVERLAP"
    assert result["forward_chronology"] == "FAIL_VALIDATION_PREDATES_TRAIN"
    assert (
        result["independent_validation"]
        == result["network_quality"]
        == result["network_edge"]
        == "BLOCKED"
    )
    assert result["admitted_samples"] == 0 and not result["test34_reassigned"]
    # Even correct chronology alone does not prove devices/campaigns or capture quality.
    result = holdout_review(
        train,
        candidate,
        train_range=[1, 2],
        candidate_range=[10, 20],
        origin_overlap=0,
        exact_duplicates=0,
    )
    assert result["forward_chronology"] == "PASS" and result["admission"] == "BLOCKED"
    candidate["session"] = "CTU-IoT-Malware-Capture-34-1"
    with pytest.raises(ValueError, match="FIXED_SPLIT"):
        holdout_review(
            train,
            candidate,
            train_range=[1, 2],
            candidate_range=[10, 20],
            origin_overlap=0,
            exact_duplicates=0,
        )


def test_overlap_campaign_unknown_or_missing_classes_fail_closed():
    from ml.iot23.capture3_validate import holdout_review

    train = {
        "session": "CTU-IoT-Malware-Capture-8-1",
        "verified_classes": {"Benign": 20, "Malicious": 30},
    }
    candidate = {
        "session": "CTU-IoT-Malware-Capture-3-1",
        "verified_classes": {"Benign": 1},
    }
    result = holdout_review(
        train,
        candidate,
        train_range=[1, 30],
        candidate_range=[20, 40],
        origin_overlap=1,
        exact_duplicates=1,
    )
    assert result["time_overlap"] == "FAIL"
    assert result["class_presence"]["validation_candidate"] == "BLOCKED"
    assert result["campaign_independence"].startswith("UNVERIFIED")
    assert result["admission"] == "BLOCKED"
