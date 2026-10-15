"""Explicit two-file Capture3 acquisition using existing reviewed transfer limits."""

import argparse
import hashlib
import json
from pathlib import Path

from ml.iot23.acquire import bounded_transfer
from ml.raw_acquisition.storage import DownloadSpec, private_directory
from ml.verified_producers.contracts import digest

BASE = "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-3-1/"
STORAGE = "data/raw/acquisition/iot23-capture-3-1-muhstik-v1"
FILES = (
    (
        BASE + "2018-05-21_capture.pcap",
        "2018-05-21_capture.pcap",
        "pcap/2018-05-21_capture.pcap",
        57919772,
        "PCAP",
    ),
    (
        BASE + "bro/conn.log.labeled",
        "conn.log.labeled",
        "bro/conn.log.labeled",
        24383537,
        "ZEEK_LABELED_FLOW",
    ),
)


def verify_plan(document: dict[str, object]) -> None:
    if document.get("manifest_digest") != digest(
        {k: v for k, v in document.items() if k != "manifest_digest"}
    ):
        raise ValueError("CAPTURE3_PLAN_TAMPERED")
    exact = {
        "contract": "iot23-capture3-download-plan:v1",
        "approval": "USER_EXPLICIT_CAPTURE3_TWO_FILES_256MIB_300S_ZERO_RETRY",
        "storage_directory": STORAGE,
        "max_files": 2,
        "expected_total_bytes": 82303309,
        "max_retries": 0,
        "archive_expansion_bytes": 0,
        "overwrite_existing": False,
        "redirects": "DENY",
        "training_authority": "NONE",
        "operational_input": "NOT_INFERABLE",
        "write_disposition": "WRITE_DENIED",
    }
    if any(
        type(document.get(k)) is not type(v) or document.get(k) != v
        for k, v in exact.items()
    ):
        raise ValueError("CAPTURE3_APPROVAL_SCOPE_MISMATCH")
    budget = document.get("download_budget_bytes")
    timeout = document.get("timeout_seconds_per_file")
    if (
        type(budget) is not int
        or not 82303309 <= budget <= 256 * 1024**2
        or type(timeout) is not int
        or not 1 <= timeout <= 300
    ):
        raise ValueError("CAPTURE3_BUDGET")
    rows = document.get("files")
    if not isinstance(rows, list) or len(rows) != 2:
        raise ValueError("CAPTURE3_FILES")
    for row, (url, name, path, size, role) in zip(rows, FILES, strict=True):
        if not isinstance(row, dict) or any(
            row.get(k) != v
            for k, v in {
                "url": url,
                "filename": name,
                "relative_path": path,
                "expected_bytes": size,
                "role": role,
                "capture_session": "CTU-IoT-Malware-Capture-3-1",
                "publisher_sha256": "UNKNOWN",
                "http_status": 200,
            }.items()
        ):
            raise ValueError("CAPTURE3_FILE_IDENTITY")


def verify_receipt(document: dict[str, object], plan: dict[str, object]) -> None:
    import re

    verify_plan(plan)
    if (
        document.get("plan_digest") != plan["manifest_digest"]
        or document.get("status") != "DOWNLOADED_NOT_ADMITTED"
        or document.get("actual_total_bytes") != 82303309
        or document.get("archive_expansion_bytes") != 0
    ):
        raise ValueError("CAPTURE3_RECEIPT_INVALID")
    rows = document.get("files")
    if not isinstance(rows, list) or len(rows) != 2:
        raise ValueError("CAPTURE3_RECEIPT_FILES")
    for row, pinned in zip(rows, plan["files"], strict=True):
        if (
            any(
                row.get(k) != pinned[k]
                for k in (
                    "url",
                    "filename",
                    "relative_path",
                    "expected_bytes",
                    "capture_session",
                    "role",
                )
            )
            or row.get("size_bytes") != pinned["expected_bytes"]
            or row.get("http_status") != 200
            or row.get("publisher_digest_verified") is not False
            or not re.fullmatch("[a-f0-9]{64}", str(row.get("sha256")))
        ):
            raise ValueError("CAPTURE3_RECEIPT_IDENTITY")
    digest(document)


def acquire(repo: Path) -> dict[str, object]:
    plan_path = repo / "docs/iot23-capture3-download-plan.json"
    plan = json.loads(plan_path.read_text())
    verify_plan(plan)
    root = repo / plan["storage_directory"]
    if root.exists() or root.is_symlink():
        raise FileExistsError("CAPTURE3_ALREADY_STARTED_NO_RETRY")
    private_directory(root)
    result = {
        "contract": "iot23-capture3-acquisition:v1",
        "plan_digest": plan["manifest_digest"],
        "plan_sha256": hashlib.sha256(plan_path.read_bytes()).hexdigest(),
        "status": "IN_PROGRESS",
        "files": [],
        "archive_expansion_bytes": 0,
    }
    try:
        total = 0
        for row in plan["files"]:
            if total + row["expected_bytes"] > plan["download_budget_bytes"]:
                raise ValueError("CAPTURE3_CUMULATIVE_BUDGET")
            spec = DownloadSpec(
                row["url"],
                row["filename"],
                row["expected_bytes"],
                row["expected_bytes"],
                ("application/vnd.tcpdump.pcap",)
                if row["role"] == "PCAP"
                else ("text/plain",),
                timeout_seconds=plan["timeout_seconds_per_file"],
                allow_missing_content_type=row["role"] == "ZEEK_LABELED_FLOW",
            )
            received = bounded_transfer(spec, (root / row["relative_path"]).parent)
            result["files"].append(
                {
                    **received,
                    "relative_path": row["relative_path"],
                    "capture_session": row["capture_session"],
                    "role": row["role"],
                }
            )
            total += received["size_bytes"]
            (root / "acquisition.json").write_text(json.dumps(result, indent=2) + "\n")
        result.update(status="DOWNLOADED_NOT_ADMITTED", actual_total_bytes=total)
        verify_receipt(result, plan)
    except (ValueError, OSError, TimeoutError) as exc:
        result.update(status="FAILED_NO_RETRY", failure=str(exc)[:200])
        raise
    finally:
        (root / "acquisition.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--execute-approved-two-files", action="store_true", required=True
    )
    parser.parse_args()
    print(json.dumps(acquire(Path(__file__).resolve().parents[3]), indent=2))
