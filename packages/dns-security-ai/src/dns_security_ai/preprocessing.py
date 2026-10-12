"""Reproduce supplied detector float32 → named scaler transform → INT8 exactly."""

import numpy as np

from dns_security_ai.contracts import FEATURE_NAMES
from dns_security_ai.errors import DNSArtifactError, DNSInferenceError


def validate_scaler(scaler: object) -> None:
    from sklearn.preprocessing import StandardScaler

    if (
        type(scaler) is not StandardScaler
        or scaler.n_features_in_ != 9
        or tuple(getattr(scaler, "feature_names_in_", ())) != FEATURE_NAMES
        or not scaler.with_mean
        or not scaler.with_std
    ):
        raise DNSArtifactError("Scaler type, configuration or feature order differs")
    for name in ("mean_", "scale_", "var_"):
        value = np.asarray(getattr(scaler, name))
        if value.shape != (9,) or not np.isfinite(value).all():
            raise DNSArtifactError("Invalid trained scaler statistics")
    if not (scaler.scale_ > 0).all() or not (scaler.var_ >= 0).all():
        raise DNSArtifactError("Invalid scaler scales or variances")
    if float(scaler.n_samples_seen_) != 162880:
        raise DNSArtifactError("Scaler training sample metadata differs from reviewed bundle")


def quantize_input(matrix: np.ndarray, scaler: object, scale: float, zero: int) -> np.ndarray:
    import pandas as pd

    values = np.array(matrix, dtype=np.float32, copy=True)
    if values.shape != (1, 9) or not np.isfinite(values).all():
        raise DNSInferenceError("Expected one finite DNS feature row")
    if not np.isfinite(scale) or scale <= 0 or not -128 <= zero <= 127:
        raise DNSArtifactError("Invalid input quantization metadata")
    transformed = scaler.transform(pd.DataFrame(values, columns=FEATURE_NAMES))
    if transformed.shape != (1, 9) or not np.isfinite(transformed).all():
        raise DNSInferenceError("Scaler returned invalid values")
    # Clipping is inherited from the supplied detector; not a fitted operation.
    return np.clip(np.round(transformed / scale + zero), -128, 127).astype(np.int8)


def dequantize_output(output: np.ndarray, scale: float, zero: int) -> float:
    from dns_security_ai.errors import DNSOutputError

    if output.shape != (1, 1) or output.dtype != np.int8:
        raise DNSOutputError("Expected one INT8 binary model output")
    if not np.isfinite(scale) or scale <= 0 or not -128 <= zero <= 127:
        raise DNSArtifactError("Invalid output quantization metadata")
    result = float(((output.astype(np.float32) - zero) * scale)[0, 0])
    if not np.isfinite(result) or not 0 <= result <= 1:
        raise DNSOutputError("Invalid malicious probability; no score coercion is allowed")
    return result
