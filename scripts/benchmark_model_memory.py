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
import torch.nn as nn


PROJECT_ROOT = Path("/home/geonug/kdt-linux/ML")

VALID_PATH = (
    PROJECT_ROOT
    / "data/processed/network_ml_dev_v4/validation/valid_v2_top40.parquet"
)

TOP40_PATH = (
    PROJECT_ROOT
    / "results/feature_selection/top40_features.csv"
)

SCALER_PATH = (
    PROJECT_ROOT
    / "models/network/dnn_top40_v4_scaler.joblib"
)

DNN_PATH = (
    PROJECT_ROOT
    / "models/network/dnn_top40_v4_best.pt"
)

LGBM_PATH = (
    PROJECT_ROOT
    / "models/network/lightgbm_top40_v4b2.txt"
)


class NetworkThreatDNN(nn.Module):

    def __init__(
        self,
        input_dim: int = 40,
        num_classes: int = 15,
    ):
        super().__init__()

        self.network = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.20),

            nn.Linear(128, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.20),

            nn.Linear(128, 64),
            nn.ReLU(),

            nn.Linear(64, num_classes),
        )

    def forward(self, x):
        return self.network(x)


def rss_mb() -> float:
    process = psutil.Process(os.getpid())

    return (
        process.memory_info().rss
        / 1024**2
    )


def peak_rss_mb() -> float:
    # Linux ru_maxrss = KiB
    return (
        resource.getrusage(
            resource.RUSAGE_SELF
        ).ru_maxrss
        / 1024
    )


def preprocess_batch(
    X: np.ndarray,
    scaler,
) -> np.ndarray:

    X = np.asarray(
        X,
        dtype=np.float32,
    )

    X[~np.isfinite(X)] = np.nan

    means = scaler.mean_.astype(
        np.float32
    )

    rows, cols = np.where(
        np.isnan(X)
    )

    if len(rows) > 0:
        X[rows, cols] = means[cols]

    return scaler.transform(
        X
    ).astype(
        np.float32,
        copy=False,
    )


def load_input(
    batch_size: int,
) -> np.ndarray:

    features = (
        pd.read_csv(TOP40_PATH)["feature"]
        .astype(str)
        .tolist()
    )

    scaler = joblib.load(
        SCALER_PATH
    )

    pf = pq.ParquetFile(
        VALID_PATH
    )

    batch = next(
        pf.iter_batches(
            batch_size=batch_size,
            columns=features,
        )
    )

    df = batch.to_pandas()

    X = (
        df[features]
        .to_numpy(
            dtype=np.float32,
            copy=True,
        )
    )

    del df, batch
    gc.collect()

    X = preprocess_batch(
        X,
        scaler,
    )

    return X


def load_fp32():

    checkpoint = torch.load(
        DNN_PATH,
        map_location="cpu",
        weights_only=False,
    )

    model = NetworkThreatDNN()

    model.load_state_dict(
        checkpoint["model_state_dict"]
    )

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

        elapsed = (
            time.perf_counter()
            - start
        )

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

    return (
        time.perf_counter()
        - start
    )


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
        args.batch_size
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

        model = lgb.Booster(
            model_file=str(
                LGBM_PATH
            )
        )


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

        "baseline_rss_mb":
            baseline_rss,

        "after_input_rss_mb":
            after_input_rss,

        "after_model_rss_mb":
            after_model_rss,

        "after_inference_rss_mb":
            after_inference_rss,

        "peak_rss_mb":
            peak,

        "model_load_delta_mb":
            after_model_rss
            - after_input_rss,

        "peak_delta_from_baseline_mb":
            peak
            - baseline_rss,

        "elapsed_50_runs_sec":
            elapsed,
    }


    print(
        json.dumps(
            result,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()