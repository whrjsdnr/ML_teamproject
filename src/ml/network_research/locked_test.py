"""Seal selection before opening test34. A failed attempt remains consumed/UNKNOWN."""

import json
import platform
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import sklearn

from ml.iot23.inspect import file_sha256
from ml.network_research.artifacts import load_research
from ml.network_research.dataset import (
    acquisition,
    build_session,
    leakage,
    load_split,
    seal,
    store_split,
    verify_seal,
    write_new,
)
from ml.network_research.evaluation import matrix, metrics, probabilities
from ml.verified_producers.contracts import digest


def code_identity(repo: Path) -> dict[str, str]:
    files = sorted((repo / "src/ml/network_research").glob("*.py"))
    files += [
        repo / "src/ml/verified_producers/network_v1_1.py",
        repo / "src/ml/ctu13/flows.py",
        repo / "src/ml/ctu13/pcap.py",
        repo / "src/ml/iot23/zeek.py",
    ]
    return {str(p.relative_to(repo)): file_sha256(p) for p in files}


def create_lock(repo: Path, data: Path, artifacts: Path) -> dict:
    selection = json.loads((artifacts / "selection.json").read_text())
    verify_seal(selection)
    _, train = load_split(data, "train")
    _, validation = load_split(data, "validation")
    _, diagnostic = load_split(data, "diagnostic")
    selected = {}
    for role in ("quality", "edge"):
        name = selection["selection"][role]
        report = next(r for r in selection["candidates"] if r["candidate"] == name)
        verify_seal(report)
        model, actual = load_research(
            artifacts / name, trusted_manifest_digest=report["manifest_digest"]
        )
        if actual != report:
            raise ValueError("SELECTION_ARTIFACT_MISMATCH")
        del model
        selected[role] = {
            "candidate": name,
            "manifest_digest": report["manifest_digest"],
            "model_sha256": report["model_sha256"],
            "threshold": report["threshold"],
        }
    sources = acquisition(
        repo
    )  # Hash identities only; no test parsing/feature generation.
    _, raw, label = sources["test"]
    return seal(
        {
            "contract": "network-research-test-lock:v1",
            "status": "RESEARCH_ONLY",
            "created_at": datetime.now(UTC).isoformat(),
            "selected": selected,
            "selection_digest": selection["manifest_digest"],
            "train_digest": train["manifest_digest"],
            "validation_digest": validation["manifest_digest"],
            "diagnostic_digest": diagnostic["manifest_digest"],
            "test_raw_sha256": raw["sha256"],
            "test_label_sha256": label["sha256"],
            "evaluation_code_sha256": code_identity(repo),
            "sklearn_version": sklearn.__version__,
            "numpy_version": np.__version__,
            "python_version": platform.python_version(),
            "test_session": "34-1",
            "test_role": "FINAL_EVALUATION_ONLY_NOT_TRAINING_OR_SELECTION",
            "blind_holdout": False,
            "previous_label_binding_inspection": True,
            "attempt_budget": 1,
            "automatic_retry": False,
            "operational_promotion": False,
        }
    )


def verify_lock(lock: dict, repo: Path, *, trusted_digest: str) -> None:
    verify_seal(lock)
    if (
        lock["manifest_digest"] != trusted_digest
        or lock["evaluation_code_sha256"] != code_identity(repo)
        or lock["test_session"] != "34-1"
        or lock["attempt_budget"] != 1
        or lock["operational_promotion"] is not False
        or lock["sklearn_version"] != sklearn.__version__
        or lock["numpy_version"] != np.__version__
        or lock["python_version"] != platform.python_version()
    ):
        raise ValueError("TEST_LOCK_MISMATCH")


def final_evaluation(
    repo: Path, data: Path, artifacts: Path, *, trusted_lock_digest: str
) -> dict:
    lock = json.loads((artifacts / "test-lock.json").read_text())
    verify_lock(lock, repo, trusted_digest=trusted_lock_digest)
    selection = json.loads((artifacts / "selection.json").read_text())
    verify_seal(selection)
    if selection["manifest_digest"] != lock["selection_digest"]:
        raise ValueError("SELECTION_CHANGED_AFTER_LOCK")
    splits = {}
    for role in ("train", "validation", "diagnostic"):
        rows, report = load_split(data, role)
        if report["manifest_digest"] != lock[role + "_digest"]:
            raise ValueError("DATASET_CHANGED_AFTER_LOCK")
        splits[role] = rows
    models = {}
    for role, binding in lock["selected"].items():
        model, report = load_research(
            artifacts / binding["candidate"],
            trusted_manifest_digest=binding["manifest_digest"],
        )
        if (
            report["threshold"] != binding["threshold"]
            or report["model_sha256"] != binding["model_sha256"]
        ):
            raise ValueError("THRESHOLD_OR_MODEL_CHANGED_AFTER_LOCK")
        models[role] = model
    source = acquisition(repo)["test"]
    if (
        source[1]["sha256"] != lock["test_raw_sha256"]
        or source[2]["sha256"] != lock["test_label_sha256"]
    ):
        raise ValueError("TEST_SOURCE_CHANGED")
    # O_EXCL write reserves the attempt before first test packet read. Never cleared
    # on errors/crash. Existing reservation means BLOCKED, not automatic retry.
    write_new(
        artifacts / "test-attempt.json",
        seal(
            {
                "lock_digest": trusted_lock_digest,
                "started_at": datetime.now(UTC).isoformat(),
                "state": "CONSUMED_RESULT_UNKNOWN_UNTIL_RECEIPT",
            }
        ),
    )
    rows, manifest = build_session(*source, "test")
    checks = {role + "__test": leakage(old, rows) for role, old in splits.items()}
    store_split(data, "test", rows, manifest)
    x, y = matrix(rows)
    selected_results = {}
    seen = {r["feature_values_digest"] for r in splits["train"] + splits["validation"]}
    novel = np.asarray([r["feature_values_digest"] not in seen for r in rows])
    for role, model in models.items():
        p = probabilities(model, x)  # One final prediction per selected model.
        selected_results[role] = {
            "metrics": metrics(y, p, lock["selected"][role]["threshold"]),
            "prediction_digest": digest(p.tolist()),
            "novel_feature_values_n": int(novel.sum()),
            "novel_feature_values_metrics": metrics(
                y[novel], p[novel], lock["selected"][role]["threshold"]
            )
            if novel.any()
            else None,
        }
    result = seal(
        {
            "status": "RESEARCH_EVALUATED",
            "operational_promotion": False,
            "test_lock_digest": trusted_lock_digest,
            "test_dataset": manifest,
            "results": selected_results,
            "leakage": checks,
            "evaluation_passes": 1,
            "predictions_per_selected_model": 1,
            "limitations": [
                "PREVIOUSLY_INSPECTED_NOT_BLIND",
                "DEVICE_CAMPAIGN_UNVERIFIED",
                "CAPTURE_QUALITY_UNKNOWN",
                "NO_OPERATIONAL_GENERALIZATION",
                "VALIDATION_PREDATES_TRAIN_RESEARCH_PROTOCOL",
            ],
        }
    )
    write_new(artifacts / "final-test-result.json", result)
    return result


def diagnostic_evaluation(data: Path, artifacts: Path) -> dict:
    selection = json.loads((artifacts / "selection.json").read_text())
    verify_seal(selection)
    rows, manifest = load_split(data, "diagnostic")
    x, y = matrix(rows)
    results = {}
    for role in ("quality", "edge"):
        name = selection["selection"][role]
        expected = next(r for r in selection["candidates"] if r["candidate"] == name)
        model, report = load_research(
            artifacts / name, trusted_manifest_digest=expected["manifest_digest"]
        )
        results[role] = metrics(y, probabilities(model, x), report["threshold"])
    return seal(
        {
            "status": "AUXILIARY_DIAGNOSTIC_ONLY_NO_SELECTION",
            "dataset_digest": manifest["manifest_digest"],
            "results": results,
            "limitation": "ONLY_FOUR_MALICIOUS_FLOWS_NOT_OPERATIONAL_EVIDENCE",
        }
    )
