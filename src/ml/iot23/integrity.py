"""Snapshot/plan identity and explicit fail-closed admission, without training."""

from ml.raw_acquisition.selection import verify_selection_plan
from ml.verified_producers.contracts import digest

GATES = (
    "raw_integrity",
    "label_integrity",
    "binding",
    "producer",
    "golden_pair",
    "manifest",
    "split_leakage",
    "holdout",
    "label_provenance",
    "capture_quality",
)


def verify_acquisition(document: dict[str, object], plan: dict[str, object]) -> None:
    import re

    verify_selection_plan(plan)
    # File-byte SHA is also stored; validate the semantic pinned plan separately.
    if (
        document.get("status") != "DOWNLOADED_NOT_ADMITTED"
        or document.get("actual_total_bytes") != plan["expected_total_bytes"]
        or document.get("archive_expansion_bytes") != 0
        or document.get("download_budget_bytes") != plan["download_budget_bytes"]
    ):
        raise ValueError("ACQUISITION_MANIFEST_INVALID")
    files = document.get("files")
    if not isinstance(files, list) or len(files) != 6:
        raise ValueError("ACQUISITION_FILE_LIST")
    for row, expected in zip(files, plan["files"], strict=True):
        if (
            not isinstance(row, dict)
            or any(
                row.get(k) != expected[k]
                for k in (
                    "url",
                    "filename",
                    "expected_bytes",
                    "relative_path",
                    "capture_session",
                    "role",
                )
            )
            or row.get("size_bytes") != expected["expected_bytes"]
            or row.get("http_status") != 200
            or not re.fullmatch("[a-f0-9]{64}", str(row.get("sha256")))
        ):
            raise ValueError("ACQUISITION_SOURCE_IDENTITY_MISMATCH")
    # Ensure canonical digest can encode all values without NaN/Infinity.
    digest(document)
    # Preserve explicit absence of publisher checksums, do not upgrade local SHA.
    if any(row.get("publisher_digest_verified") is not False for row in files):
        raise ValueError("PUBLISHER_DIGEST_NOT_AVAILABLE")


def admission(gates: dict[str, str]) -> str:
    if set(gates) != set(GATES) or any(gates.get(name) != "PASS" for name in GATES):
        return "BLOCKED"
    return "READY_FOR_RETRAINING"


def verify_manifest(document: dict[str, object]) -> None:
    if document.get("manifest_digest") != digest(
        {k: v for k, v in document.items() if k != "manifest_digest"}
    ):
        raise ValueError("DATASET_MANIFEST_TAMPERED")
    if document.get("admission") != admission(document.get("gates", {})):
        raise ValueError("ADMISSION_GATE_MISMATCH")

    if (
        document.get("operational_input") != "NOT_INFERABLE"
        or document.get("write_disposition") != "WRITE_DENIED"
    ):
        raise ValueError("OPERATIONAL_AUTHORITY_NOT_GRANTED")
    gates = document.get("gates", {})
    sessions = document.get("sessions", [])
    if gates.get("holdout") == "PASS" and (
        len(sessions) != 3
        or any(
            not s.get("verified_class_distribution", {}).get("Malicious")
            or not s.get("verified_class_distribution", {}).get("Benign")
            for s in sessions
        )
    ):
        raise ValueError("HOLDOUT_CLASS_COVERAGE_MISSING")
    if gates.get("capture_quality") == "PASS" and (
        not sessions
        or any(
            s.get("capture_quality") != "CONFIRMED_NO_DROPS_IN_WINDOW" for s in sessions
        )
    ):
        raise ValueError("CAPTURE_QUALITY_NOT_VERIFIED")
    if (
        gates.get("split_leakage") == "PASS"
        and document.get("split", {}).get("physical_host_and_campaign_independence")
        != "VERIFIED"
    ):
        raise ValueError("INDEPENDENCE_NOT_VERIFIED")
