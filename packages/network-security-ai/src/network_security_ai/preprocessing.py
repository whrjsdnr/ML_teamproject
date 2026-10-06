"""DNN inference preprocessing using an already fitted, trusted training scaler."""

from typing import Protocol

import numpy as np

from network_security_ai.errors import SecurityAIInferenceError


class FittedScaler(Protocol):
    mean_: np.ndarray

    def transform(self, matrix: np.ndarray) -> np.ndarray: ...


def preprocess_dnn_batch(matrix: np.ndarray, scaler: FittedScaler) -> np.ndarray:
    """Canonical Top40 batch: copy, impute nonfinite values, transform; never fit."""
    values = np.array(matrix, dtype=np.float32, copy=True)
    if values.ndim != 2 or values.shape[1] != 40:
        raise SecurityAIInferenceError("DNN input must be a Top40 matrix")
    means = np.asarray(scaler.mean_, dtype=np.float32)
    if means.shape != (40,) or not np.isfinite(means).all():
        raise SecurityAIInferenceError("DNN scaler has invalid training means")
    rows, columns = np.where(~np.isfinite(values))
    values[rows, columns] = means[columns]
    transformed = np.asarray(scaler.transform(values), dtype=np.float32)
    if transformed.shape != values.shape or not np.isfinite(transformed).all():
        raise SecurityAIInferenceError("DNN scaler returned invalid input")
    return transformed
