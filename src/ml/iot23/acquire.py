"""Explicit six-file acquisition with isolated per-file hard watchdog, no retries."""

import argparse
import hashlib
import json
import multiprocessing
import time
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from ml.raw_acquisition.selection import verify_selection_plan
from ml.raw_acquisition.storage import (
    DownloadSpec,
    fetch_reviewed_file,
    private_directory,
)


def _transfer(spec: DownloadSpec, directory: Path, connection) -> None:
    try:
        receipt = fetch_reviewed_file(spec, directory)
        connection.send({"receipt": asdict(receipt)})
    except (ValueError, OSError, TimeoutError) as exc:
        connection.send({"error_type": type(exc).__name__, "error": str(exc)[:160]})
    finally:
        connection.close()


def bounded_transfer(spec: DownloadSpec, directory: Path) -> dict[str, object]:
    root = private_directory(directory)
    if any(root.iterdir()):
        raise FileExistsError("EMPTY_TRANSFER_DIRECTORY_REQUIRED")
    ctx = multiprocessing.get_context("spawn")
    receive, send = ctx.Pipe(duplex=False)
    child = ctx.Process(target=_transfer, args=(spec, root, send))
    started = time.monotonic()
    child.start()
    send.close()
    try:
        child.join(max(0.0, spec.timeout_seconds - (time.monotonic() - started)))
        if child.is_alive():
            child.terminate()
            child.join(2)
            if child.is_alive():
                child.kill()
                child.join()
            raise TimeoutError("FILE_HARD_WATCHDOG")
        if child.exitcode != 0 or not receive.poll():
            raise ValueError("TRANSFER_PROCESS_FAILED")
        result = receive.recv()
        if "receipt" not in result:
            raise ValueError("TRANSFER_FAILED:" + str(result))
        return {
            **result["receipt"],
            "url": spec.url,
            "expected_bytes": spec.expected_bytes,
            "http_status": 200,
            "duration_seconds": time.monotonic() - started,
            "acquired_at": datetime.now(UTC).isoformat(),
        }
    finally:
        receive.close()
        # This directory was empty before our one child started. Never clean
        # caller-owned files or a different acquisition's partials.
        for partial in root.glob(".download-*"):
            if partial.is_file() and not partial.is_symlink():
                partial.unlink()


def acquire(root: Path) -> dict[str, object]:
    plan_path = root / "docs/network-training-download-plan.json"
    plan = json.loads(plan_path.read_text())
    verify_selection_plan(plan)
    destination = root / plan["storage_directory"]
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("ACQUISITION_ALREADY_STARTED_NO_AUTOMATIC_RETRY")
    private_directory(destination)
    result = {
        "contract": "iot23-acquisition:v1",
        "approval": "USER_EXPLICIT_SIX_FILES_256MIB_300SECONDS_ZERO_RETRY",
        "plan_sha256": hashlib.sha256(plan_path.read_bytes()).hexdigest(),
        "files": [],
        "download_budget_bytes": plan["download_budget_bytes"],
        "archive_expansion_bytes": 0,
        "status": "IN_PROGRESS",
    }
    receipt_path = destination / "acquisition.json"
    try:
        total = 0
        for row in plan["files"]:
            if total + row["expected_bytes"] > plan["download_budget_bytes"]:
                raise ValueError("CUMULATIVE_DOWNLOAD_LIMIT")
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
            receipt = bounded_transfer(
                spec, (destination / row["relative_path"]).parent
            )
            result["files"].append(
                {
                    **receipt,
                    "relative_path": row["relative_path"],
                    "capture_session": row["capture_session"],
                    "role": row["role"],
                }
            )
            total += receipt["size_bytes"]
            receipt_path.write_text(json.dumps(result, indent=2) + "\n")
        result.update(status="DOWNLOADED_NOT_ADMITTED", actual_total_bytes=total)
    except (ValueError, OSError, TimeoutError) as exc:
        result.update(status="FAILED_NO_RETRY", failure=str(exc)[:300])
        raise
    finally:
        receipt_path.write_text(json.dumps(result, indent=2) + "\n")

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--execute-approved-six-files", action="store_true", required=True
    )
    parser.parse_args()
    print(json.dumps(acquire(Path(__file__).resolve().parents[3]), indent=2))
