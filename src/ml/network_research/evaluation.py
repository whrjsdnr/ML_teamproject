"""Finite research metrics and predeclared validation-only selection."""

import time

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    roc_auc_score,
)

from ml.verified_producers.contracts import NETWORK_NAMES

SEED = 20261015
THRESHOLDS = tuple(i / 20 for i in range(1, 20))
SELECTION = {
    "quality": "MAX_VALIDATION_AP_THEN_F1_RECALL_NEGATIVE_FPR_NEGATIVE_BRIER",
    "edge": "MIN_SINGLE_ROW_MEDIAN_CPU_LATENCY_AMONG_RECALL_GE_0.8_FPR_LE_0.1; ELSE_MAX_F1_AP_RESEARCH_LIMITED",
    "threshold": "MAX_F1_THEN_RECALL_THEN_NEGATIVE_FPR_THEN_CLOSEST_TO_0.5; FIXED_GRID_0.05_TO_0.95",
    "test": "ONE_FINAL_PASS_BOTH_SELECTED_MODELS_NO_TUNING; PREVIOUSLY_INSPECTED_SESSION_NOT_BLIND",
}


def matrix(
    rows: list[dict], feature_names: list[str] | tuple[str, ...] = NETWORK_NAMES
):
    if tuple(feature_names) != NETWORK_NAMES or not rows:
        raise ValueError("FEATURE_ORDER_OR_EMPTY_DATASET")
    x = np.asarray([r["values"] for r in rows])
    y = np.asarray([r["y"] for r in rows])
    if (
        x.shape != (len(rows), 14)
        or not np.isfinite(x).all()
        or not np.isin(y, [0, 1]).all()
    ):
        raise ValueError("INVALID_FEATURE_OR_LABEL")
    converted = x.astype(np.float32)
    if not np.isfinite(converted).all() or not np.equal(x, converted).all():
        raise ValueError("FLOAT32_CONTRACT")
    return converted, y.astype(np.int8)


def probabilities(model, x: np.ndarray) -> np.ndarray:
    if list(model.classes_) != [0, 1]:
        raise ValueError("INVALID_MODEL_CLASSES")
    p = np.asarray(model.predict_proba(x))
    if (
        p.shape != (len(x), 2)
        or not np.isfinite(p).all()
        or np.any((p < 0) | (p > 1))
        or not np.allclose(p.sum(axis=1), 1, atol=1e-6)
    ):
        raise ValueError("INVALID_MODEL_OUTPUT")
    return p[:, 1]


def metrics(y: np.ndarray, p: np.ndarray, threshold: float) -> dict:
    y, p = np.asarray(y), np.asarray(p)
    if (
        y.ndim != 1
        or not len(y)
        or p.shape != y.shape
        or not np.isin(y, [0, 1]).all()
        or not np.isfinite(p).all()
        or np.any((p < 0) | (p > 1))
        or not 0 < threshold < 1
    ):
        raise ValueError("INVALID_METRIC_INPUT")
    pred = p >= threshold
    tn, fp, fn, tp = [int(v) for v in confusion_matrix(y, pred, labels=[0, 1]).ravel()]

    def ratio(a, b):
        return a / b if b else None

    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    bins = []
    ece = 0.0
    for i in range(10):
        mask = (p >= i / 10) & ((p < (i + 1) / 10) if i < 9 else (p <= 1))
        if mask.any():
            confidence, observed = float(p[mask].mean()), float(y[mask].mean())
            ece += int(mask.sum()) / len(y) * abs(confidence - observed)
            bins.append(
                {
                    "lower": i / 10,
                    "count": int(mask.sum()),
                    "mean_probability": confidence,
                    "observed_malicious_fraction": observed,
                }
            )
    both = len(np.unique(y)) == 2
    return {
        "n": len(y),
        "class_counts": {"benign": tn + fp, "malicious": tp + fn},
        "threshold": threshold,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
        "precision": precision,
        "recall": recall,
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "pr_auc_average_precision": float(average_precision_score(y, p))
        if both
        else None,
        "roc_auc": float(roc_auc_score(y, p)) if both else None,
        "fpr": ratio(fp, fp + tn),
        "fnr": ratio(fn, fn + tp),
        "brier": float(brier_score_loss(y, p)),
        "ece_10_bins": ece,
        "calibration_bins": bins,
        "single_class_metrics": "N/A" if not both else "BOTH_CLASSES_PRESENT",
    }


def threshold_from_validation(y, p) -> float:
    if len(np.unique(y)) != 2:
        raise ValueError("VALIDATION_REQUIRES_BOTH_CLASSES")

    def rank(t):
        m = metrics(y, p, t)
        return m["f1"], m["recall"], -m["fpr"], -abs(t - 0.5)

    return max(THRESHOLDS, key=rank)


def benchmark(model, x: np.ndarray) -> dict:
    # CPU process time and real perf_counter measured separately. Bounded repetitions.
    probabilities(model, x[:1])
    wall, cpu = [], []
    for _ in range(100):
        a, b = time.perf_counter_ns(), time.process_time_ns()
        probabilities(model, x[:1])
        cpu.append(time.process_time_ns() - b)
        wall.append(time.perf_counter_ns() - a)
    a, b = time.perf_counter(), time.process_time()
    probabilities(model, x)
    elapsed, consumed = time.perf_counter() - a, time.process_time() - b
    return {
        "single_row_repetitions": 100,
        "warmup_calls": 1,
        "single_row_wall_p50_ms": float(np.median(wall) / 1e6),
        "single_row_wall_p95_ms": float(np.percentile(wall, 95) / 1e6),
        "single_row_cpu_p50_ms": float(np.median(cpu) / 1e6),
        "batch_n": len(x),
        "batch_wall_seconds": elapsed,
        "batch_cpu_seconds": consumed,
        "batch_flows_per_second": len(x) / elapsed,
    }
