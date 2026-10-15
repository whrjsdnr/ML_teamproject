"""Finite CPU research candidates. Train-only preprocessing; no Test input."""

import argparse
import hashlib
import json
import os
import platform
import resource
import time
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from ml.network_research.dataset import load_split, seal, write_new
from ml.network_research.evaluation import (
    SEED,
    SELECTION,
    benchmark,
    matrix,
    metrics,
    probabilities,
    threshold_from_validation,
)
from ml.verified_producers.contracts import digest
from ml.verified_producers.network_v1_1 import feature_contract, producer_contract

CANDIDATES = ("quality_rf", "quality_hgb", "edge_lr", "edge_rf", "edge_hgb")


def estimator(name: str):
    if name == "quality_rf":
        return RandomForestClassifier(
            n_estimators=128,
            max_depth=12,
            min_samples_leaf=3,
            class_weight="balanced",
            random_state=SEED,
            n_jobs=1,
        )
    if name == "quality_hgb":
        return HistGradientBoostingClassifier(
            max_iter=100,
            max_leaf_nodes=15,
            max_depth=6,
            learning_rate=0.08,
            class_weight="balanced",
            early_stopping=False,
            random_state=SEED,
        )
    if name == "edge_lr":
        return make_pipeline(
            StandardScaler(),
            LogisticRegression(
                C=1.0, max_iter=2000, class_weight="balanced", random_state=SEED
            ),
        )
    if name == "edge_rf":
        return RandomForestClassifier(
            n_estimators=24,
            max_depth=6,
            min_samples_leaf=5,
            class_weight="balanced",
            random_state=SEED,
            n_jobs=1,
        )
    if name == "edge_hgb":
        return HistGradientBoostingClassifier(
            max_iter=32,
            max_leaf_nodes=7,
            max_depth=3,
            learning_rate=0.1,
            class_weight="balanced",
            early_stopping=False,
            random_state=SEED,
        )
    raise ValueError("UNAPPROVED_RESEARCH_CANDIDATE")


def fit_candidate(data: Path, output: Path, name: str) -> dict:
    if name not in CANDIDATES:
        raise ValueError("UNKNOWN_CANDIDATE")
    train, train_manifest = load_split(data, "train")
    validation, validation_manifest = load_split(data, "validation")
    x, y = matrix(train)
    vx, vy = matrix(validation)
    if len(np.unique(y)) != 2:
        raise ValueError("TRAIN_REQUIRES_TWO_CLASSES")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    model = estimator(name)
    before = int(Path("/proc/self/statm").read_text().split()[1]) * os.sysconf(
        "SC_PAGE_SIZE"
    )
    a, b = time.perf_counter(), time.process_time()
    model.fit(x, y)
    wall, cpu = time.perf_counter() - a, time.process_time() - b
    prediction = probabilities(model, vx)
    threshold = threshold_from_validation(vy, prediction)
    joblib.dump(model, output / "model.joblib", compress=0, protocol=5)
    (output / "model.joblib").chmod(0o600)
    model_bytes = (output / "model.joblib").read_bytes()
    measurement = benchmark(model, vx)
    scaler = model.steps[0][1] if hasattr(model, "steps") else None
    report = seal(
        {
            "status": "RESEARCH_ONLY",
            "operational_promotion": False,
            "model_id": "linux-network14-research-v1-" + name,
            "candidate": name,
            "model_sha256": hashlib.sha256(model_bytes).hexdigest(),
            "model_size_bytes": len(model_bytes),
            "producer_config_digest": digest(producer_contract()),
            "feature_contract_digest": digest(feature_contract()),
            "producer": producer_contract(),
            "feature_contract": feature_contract(),
            "train_dataset_digest": train_manifest["manifest_digest"],
            "validation_dataset_digest": validation_manifest["manifest_digest"],
            "split_roles": {
                "train": "8-1",
                "validation": "3-1",
                "diagnostic": "20-1",
                "locked_test": "34-1",
            },
            "seed": SEED,
            "hyperparameters": {k: repr(v) for k, v in model.get_params().items()},
            "sklearn_version": sklearn.__version__,
            "numpy_version": np.__version__,
            "joblib_version": joblib.__version__,
            "python_version": platform.python_version(),
            "platform": platform.system(),
            "threads": 1,
            "threshold": threshold,
            "selection_protocol": SELECTION,
            "train_only_preprocessing": {
                "scaler": type(scaler).__name__ if scaler else "NONE_TREE_MODEL",
                "fit_rows": len(x),
                "fitted_samples": int(scaler.n_samples_seen_) if scaler else None,
                "imputation": "NONE_REJECT_MISSING",
                "resampling": "NONE",
                "class_weight": "balanced",
            },
            "validation_metrics": metrics(vy, prediction, threshold),
            "validation_prediction_digest": digest(prediction.tolist()),
            "benchmark": measurement,
            "training": {
                "wall_seconds": wall,
                "cpu_seconds": cpu,
                "rss_before_fit_bytes": before,
                "peak_process_rss_kib": resource.getrusage(
                    resource.RUSAGE_SELF
                ).ru_maxrss,
                "peak_scope": "ISOLATED_CANDIDATE_PROCESS_INCLUDING_DATA_LOAD_TRAIN_AND_VALIDATION",
            },
        }
    )
    write_new(output / "artifact.json", report)
    return report


def select(reports: list[dict]) -> dict:
    def quality_rank(r):
        m = r["validation_metrics"]
        return (
            m["pr_auc_average_precision"],
            m["f1"],
            m["recall"],
            -m["fpr"],
            -m["brier"],
        )

    q = max(
        (r for r in reports if r["candidate"].startswith("quality_")), key=quality_rank
    )
    edges = [r for r in reports if r["candidate"].startswith("edge_")]
    eligible = [
        r
        for r in edges
        if r["validation_metrics"]["recall"] >= 0.8
        and r["validation_metrics"]["fpr"] <= 0.1
    ]
    e = (
        min(
            eligible,
            key=lambda r: (
                r["benchmark"]["single_row_cpu_p50_ms"],
                r["model_size_bytes"],
                r["candidate"],
            ),
        )
        if eligible
        else max(
            edges,
            key=lambda r: (
                r["validation_metrics"]["f1"],
                r["validation_metrics"]["pr_auc_average_precision"],
            ),
        )
    )
    return {
        "quality": q["candidate"],
        "edge": e["candidate"],
        "edge_accuracy_eligibility": bool(eligible),
        "scope": "RESEARCH_ONLY_NO_OPERATIONAL_PROMOTION",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--candidate", required=True, choices=CANDIDATES)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (3 * 1024**3, 3 * 1024**3))
    print(json.dumps(fit_candidate(args.data, args.output, args.candidate)))
