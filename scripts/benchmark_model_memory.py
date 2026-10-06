from __future__ import annotations

import argparse
import gc
import json
import os
import resource
import time
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
import psutil
import pyarrow.parquet as pq
import torch

from network_security_ai.predictors import build_dnn
from network_security_ai.preprocessing import preprocess_dnn_batch

PROJECT_ROOT = Path(__file__).resolve().parents[1]

VALID_PATH = PROJECT_ROOT / "data/processed/network_ml_dev_v4/validation/valid_v2_top40.parquet"

TOP40_PATH = PROJECT_ROOT / "results/feature_selection/top40_features.csv"

SCALER_PATH = PROJECT_ROOT / "models/network/dnn_top40_v4_scaler.joblib"

DNN_PATH = PROJECT_ROOT / "models/network/dnn_top40_v4_best.pt"

LGBM_PATH = PROJECT_ROOT / "models/network/lightgbm_top40_v4b2.txt"


def NetworkThreatDNN(input_dim: int = 40, num_classes: int = 15):
    """Compatibility factory; the inference package owns the reviewed architecture."""
    if input_dim != 40 or num_classes != 15:
        raise ValueError("The V4 model requires 40 features and 15 classes")
    return build_dnn()


def rss_mb() -> float:
    process = psutil.Process(os.getpid())

    return process.memory_info().rss / 1024**2


def peak_rss_mb() -> float:
    # Linux ru_maxrss = KiB
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def preprocess_batch(X: np.ndarray, scaler) -> np.ndarray:
    """Compatibility name for report scripts; never fit the scaler."""
    return preprocess_dnn_batch(X, scaler)


def load_input(
    batch_size: int,
    *,
    scale_for_dnn: bool = True,
) -> np.ndarray:

    features = pd.read_csv(TOP40_PATH)["feature"].astype(str).tolist()

    pf = pq.ParquetFile(VALID_PATH)

    batch = next(
        pf.iter_batches(
            batch_size=batch_size,
            columns=features,
        )
    )

    df = batch.to_pandas()

    X = df[features].to_numpy(
        dtype=np.float32,
        copy=True,
    )

    del df, batch
    gc.collect()

    if scale_for_dnn:
        X = preprocess_batch(X, joblib.load(SCALER_PATH))
    else:
        # LightGBM was trained on raw Top40 features, not DNN-scaled features.
        X[~np.isfinite(X)] = np.nan

    return X


def load_fp32():

    checkpoint = torch.load(
        DNN_PATH,
        map_location="cpu",
        weights_only=True,
    )

    model = NetworkThreatDNN()

    model.load_state_dict(checkpoint["model_state_dict"])

    model.eval()

    return model


def load_int8():

    from torchao.quantization import (
        Int8DynamicActivationInt8WeightConfig,
        quantize_,
    )

    model = load_fp32()

    quantize_(
        model,
        Int8DynamicActivationInt8WeightConfig(),
    )

    model.eval()

    return model


def run_torch(
    model,
    X,
    runs=50,
):

    tensor = torch.from_numpy(X)

    with torch.inference_mode():
        # warm-up
        for _ in range(10):
            _ = model(tensor)

        start = time.perf_counter()

        for _ in range(runs):
            _ = model(tensor)

        elapsed = time.perf_counter() - start

    return elapsed


def run_lightgbm(
    model,
    X,
    runs=50,
):

    for _ in range(10):
        _ = model.predict(
            X,
            num_threads=1,
        )

    start = time.perf_counter()

    for _ in range(runs):
        _ = model.predict(
            X,
            num_threads=1,
        )

    return time.perf_counter() - start


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--model",
        required=True,
        choices=[
            "fp32",
            "int8",
            "lightgbm",
        ],
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=4096,
    )

    args = parser.parse_args()

    torch.set_num_threads(1)

    try:
        torch.set_num_interop_threads(1)
    except RuntimeError:
        pass

    # ----------------------------------
    # Baseline
    # ----------------------------------

    gc.collect()

    baseline_rss = rss_mb()

    # ----------------------------------
    # Input
    # ----------------------------------

    X = load_input(
        args.batch_size,
        scale_for_dnn=args.model != "lightgbm",
    )

    after_input_rss = rss_mb()

    # ----------------------------------
    # Model
    # ----------------------------------

    if args.model == "fp32":
        model = load_fp32()

    elif args.model == "int8":
        model = load_int8()

    else:
        model = lgb.Booster(model_file=str(LGBM_PATH))

    after_model_rss = rss_mb()

    # ----------------------------------
    # Inference
    # ----------------------------------

    if args.model in {
        "fp32",
        "int8",
    }:
        elapsed = run_torch(
            model,
            X,
        )

    else:
        elapsed = run_lightgbm(
            model,
            X,
        )

    after_inference_rss = rss_mb()

    peak = peak_rss_mb()

    result = {
        "model": args.model,
        "batch_size": args.batch_size,
        "baseline_rss_mb": baseline_rss,
        "after_input_rss_mb": after_input_rss,
        "after_model_rss_mb": after_model_rss,
        "after_inference_rss_mb": after_inference_rss,
        "peak_rss_mb": peak,
        "model_load_delta_mb": after_model_rss - after_input_rss,
        "peak_delta_from_baseline_mb": peak - baseline_rss,
        "elapsed_50_runs_sec": elapsed,
    }

    print(
        json.dumps(
            result,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
