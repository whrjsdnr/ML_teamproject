"""Validate a pending Network14 acquisition plan; never authorizes I/O/training.

Existing pending_manifest is v1.0.0-only. Do not widen that contract to admit
v1.1.0 data: this small, separate validator checks planning metadata only.
"""

from pathlib import PurePosixPath

from ml.raw_acquisition.storage import DownloadSpec
from ml.verified_producers.contracts import digest
from ml.verified_producers.network_v1_1 import feature_contract, producer_contract

_BASE = "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/"
_REVIEWED = {
    "8-1": ("2018-07-31-15-15-09-192.168.100.113.pcap", 2098362, 1431000),
    "20-1": ("2018-10-02-13-12-30-192.168.100.103.pcap", 4057401, 419604),
    "34-1": ("2018-12-21-15-50-14-192.168.1.195.pcap", 126317980, 2926718),
}


def verify_selection_plan(document: dict[str, object]) -> None:
    body = {k: v for k, v in document.items() if k != "manifest_digest"}
    if document.get("manifest_digest") != digest(body):
        raise ValueError("SELECTION_MANIFEST_TAMPERED")
    expected = {
        "contract_version": "network-dataset-selection-plan:v1",
        "plan_id": "iot23-network14-3sessions-v1",
        "decision": "ACQUISITION_READY",
        "download_approval": "AWAITING_EXPLICIT_USER_APPROVAL",
        "automatic_download": False,
        "new_raw_downloads": 0,
        "actual_raw_bytes_downloaded": 0,
        "new_raw_decompressed_bytes": 0,
        "storage_directory": "data/raw/acquisition/iot23-network14-3sessions-v1",
        "max_files": 6,
        "expected_total_bytes": 137251065,
        "max_retries": 0,
        "hard_process_watchdog_required": True,
        "archive_expansion_budget_bytes": 0,
        "overwrite_existing": False,
        "admission": "NOT_ADMITTED",
        "verified_matches": 0,
        "admitted_samples": 0,
        "dataset_digest": "UNKNOWN",
        "split_digest": "UNKNOWN",
        "training_authority": "NONE",
        "operational_input": "NOT_INFERABLE",
        "write_disposition": "WRITE_DENIED",
    }
    if any(
        type(body.get(k)) is not type(v) or body.get(k) != v
        for k, v in expected.items()
    ):
        raise ValueError("PENDING_SELECTION_CANNOT_GRANT_AUTHORITY")
    if body.get("model_readiness") != {
        "Network Quality": "BLOCKED",
        "Network Edge": "BLOCKED",
    }:
        raise ValueError("TRAINING_NOT_READY")
    budget = body.get("download_budget_bytes")
    timeout = body.get("timeout_seconds_per_file")
    if (
        type(budget) is not int
        or not 137251065 <= budget <= 256 * 1024**2
        or type(timeout) is not int
        or not 1 <= timeout <= 300
    ):
        raise ValueError("DOWNLOAD_BUDGET_INVALID")
    producer = body.get("producer")
    if not isinstance(producer, dict) or any(
        producer.get(k) != v
        for k, v in {
            "version": "1.1.0",
            "source_origin": "OFFLINE_PCAP",
            "feature_count": 14,
            "dtype": "float32",
            "configuration_digest": digest(producer_contract()),
            "feature_contract_digest": digest(feature_contract()),
            "compatibility": "STRUCTURAL_EXPECTATION_ONLY_ACTUAL_BYTES_BLOCKED",
            "actual_golden_pair": "NOT_RUN",
        }.items()
    ):
        raise ValueError("PRODUCER_CONTRACT_MISMATCH")
    files = body.get("files")
    if not isinstance(files, list) or len(files) != 6:
        raise ValueError("FILE_LIST_INVALID")
    expected_files = {}
    for sid, (filename, raw_bytes, label_bytes) in _REVIEWED.items():
        session = "CTU-IoT-Malware-Capture-" + sid
        expected_files[_BASE + session + "/" + filename] = (
            session,
            filename,
            raw_bytes,
            "PCAP",
            session + "/" + filename,
        )
        expected_files[_BASE + session + "/bro/conn.log.labeled"] = (
            session,
            "conn.log.labeled",
            label_bytes,
            "ZEEK_LABELED_FLOW",
            session + "/bro/conn.log.labeled",
        )
    seen = set()
    total = 0
    for row in files:
        if (
            not isinstance(row, dict)
            or row.get("url") not in expected_files
            or row["url"] in seen
        ):
            raise ValueError("UNREVIEWED_OR_DUPLICATE_FILE")
        seen.add(row["url"])
        session, filename, size, role, relative = expected_files[row["url"]]
        if (
            row.get("capture_session") != session
            or row.get("filename") != filename
            or row.get("relative_path") != relative
            or row.get("role") != role
            or type(row.get("expected_bytes")) is not int
            or row["expected_bytes"] != size
            or row.get("head_status") != 200
            or row.get("head_content_type")
            != ("application/vnd.tcpdump.pcap" if role == "PCAP" else "UNKNOWN")
            or row.get("actual_sha256") != "UNKNOWN"
            or row.get("publisher_sha256") != "UNKNOWN"
            or row.get("acquired") is not False
        ):
            raise ValueError("PENDING_FILE_IDENTITY_MISMATCH")
        path = PurePosixPath(row["relative_path"])
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("UNSAFE_STORAGE_PATH")
        if role == "PCAP":
            # Reuse current transport contract without fetching a byte.
            DownloadSpec(
                row["url"],
                filename,
                size,
                size,
                ("application/vnd.tcpdump.pcap",),
                timeout_seconds=timeout,
            )
        total += size
    if total != body["expected_total_bytes"] or total > budget:
        raise ValueError("TOTAL_BUDGET_MISMATCH")
    holdout = body.get("holdout")
    if (
        not isinstance(holdout, dict)
        or holdout.get("status") != "PROPOSED_NOT_EXECUTED"
        or holdout.get("never_random_row_split") is not True
    ):
        raise ValueError("HOLDOUT_NOT_VERIFIED")
    sessions = holdout.get("sessions")
    if not isinstance(sessions, dict) or sessions != {
        "train": ["CTU-IoT-Malware-Capture-8-1"],
        "validation": ["CTU-IoT-Malware-Capture-20-1"],
        "test": ["CTU-IoT-Malware-Capture-34-1"],
    }:
        raise ValueError("SESSION_SPLIT_LEAKAGE_OR_CHANGE")
    if any(
        holdout.get(k) != "NOT_RUN_ON_ACTUAL_DATA"
        for k in ("group_overlap_check", "duplicate_flow_check")
    ):
        raise ValueError("UNVERIFIED_SPLIT_CANNOT_CLAIM_PASS")
    label_contract = body.get("label_contract")
    if (
        not isinstance(label_contract, dict)
        or label_contract.get("raw_label_binding") != "NOT_VERIFIED"
    ):
        raise ValueError("UNVERIFIED_RAW_LABEL_BINDING")
    ctu = body.get("ctu13_s07_final")
    if (
        not isinstance(ctu, dict)
        or ctu.get("role") != "PRODUCER_DIAGNOSTIC_ONLY"
        or ctu.get("label_timezone") != "TIMEZONE_UNVERIFIED"
        or ctu.get("verified_matches") != 0
        or ctu.get("training_admission") != "BLOCKED"
    ):
        raise ValueError("CTU13_ADMISSION_BYPASS")
