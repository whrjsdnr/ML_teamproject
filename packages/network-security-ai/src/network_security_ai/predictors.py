"""Lazy, profile-specific inference. No training, TorchAO, tools or response services."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from threading import Lock
from typing import TYPE_CHECKING, Protocol

import numpy as np

from network_security_ai.contracts import (
    DeploymentProfile,
    NetworkArtifactError,
    NetworkSecurityAIConfig,
    NetworkThreatPrediction,
    Top40Contract,
)
from network_security_ai.errors import SecurityAIInferenceError, SecurityAIOutputValidationError
from network_security_ai.preprocessing import preprocess_dnn_batch
from network_security_ai.schema import ClassProbability

if TYPE_CHECKING:
    from torch import Tensor
    from torch.nn import Module

logger = logging.getLogger(__name__)


class Booster(Protocol):
    def feature_name(self) -> list[str]: ...
    def num_feature(self) -> int: ...
    def num_model_per_iteration(self) -> int: ...
    def predict(self, matrix: np.ndarray, *, num_threads: int) -> np.ndarray: ...


class Scaler(Protocol):
    mean_: np.ndarray
    scale_: np.ndarray
    n_features_in_: int

    def transform(self, matrix: np.ndarray) -> np.ndarray: ...


@dataclass(frozen=True)
class LoadedDNN:
    scaler: Scaler
    probabilities: Callable[[np.ndarray], np.ndarray]


def load_lightgbm(config: NetworkSecurityAIConfig, contract: Top40Contract) -> Booster:
    path = contract.verify_artifact(config, "lightgbm_path")
    import lightgbm as lgb

    model = lgb.Booster(model_file=str(path))
    # LightGBM replaces spaces with underscores when serializing feature names.
    if (
        model.feature_name() != [n.replace(" ", "_") for n in contract.names]
        or model.num_feature() != 40
        or model.num_model_per_iteration() != 15
    ):
        raise NetworkArtifactError("LightGBM model differs from the Top40/15-class contract")
    return model


def build_dnn() -> Module:
    """Checkpoint architecture, imported only for the edge profile."""
    import torch.nn as nn

    class NetworkThreatDNN(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.network = nn.Sequential(
                nn.Linear(40, 128),
                nn.BatchNorm1d(128),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(128, 128),
                nn.BatchNorm1d(128),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(128, 64),
                nn.ReLU(),
                nn.Linear(64, 15),
            )

        def forward(self, values: Tensor) -> Tensor:
            return self.network(values)

    return NetworkThreatDNN()


def load_dnn(config: NetworkSecurityAIConfig, contract: Top40Contract) -> LoadedDNN:
    checkpoint_path = contract.verify_artifact(config, "dnn_path")
    scaler_path = contract.verify_artifact(config, "scaler_path")
    import joblib
    import torch

    # weights_only rejects arbitrary pickle classes in this repository checkpoint.
    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=True)
    if (
        not isinstance(checkpoint, dict)
        or checkpoint.get("top40_features") != list(contract.names)
        or checkpoint.get("epoch") != 13
    ):
        raise NetworkArtifactError("DNN checkpoint differs from the validated epoch13 Top40 model")
    scaler = joblib.load(scaler_path)  # Trusted local administrator-controlled artifact only.
    if (
        scaler.n_features_in_ != 40
        or np.asarray(scaler.mean_).shape != (40,)
        or np.asarray(scaler.scale_).shape != (40,)
        or not np.isfinite(scaler.mean_).all()
        or not np.isfinite(scaler.scale_).all()
        or not (scaler.scale_ > 0).all()
    ):
        raise NetworkArtifactError("Scaler must contain 40 finite trained means/positive scales")
    if hasattr(scaler, "feature_names_in_") and tuple(scaler.feature_names_in_) != contract.names:
        raise NetworkArtifactError("Scaler feature order differs from Top40")
    model = build_dnn()
    model.load_state_dict(checkpoint["model_state_dict"], strict=True)
    model.eval()

    def probabilities(matrix: np.ndarray) -> np.ndarray:
        with torch.inference_mode():
            return model(torch.from_numpy(matrix)).softmax(dim=1).numpy()

    return LoadedDNN(scaler=scaler, probabilities=probabilities)


class _Predictor:
    def __init__(self, config: NetworkSecurityAIConfig, contract: Top40Contract) -> None:
        self.config = config
        self.contract = contract
        self._lock = Lock()

    def _probabilities(self, matrix: np.ndarray) -> np.ndarray:
        raise NotImplementedError

    def predict(self, features: Mapping[str, object]) -> NetworkThreatPrediction:
        matrix = self.contract.matrix(features)
        started = time.perf_counter_ns()
        try:
            with self._lock:
                raw = np.asarray(self._probabilities(matrix), dtype=np.float64)
            latency = (time.perf_counter_ns() - started) / 1_000_000
            if raw.shape != (1, 15) or not np.isfinite(raw).all():
                raise SecurityAIOutputValidationError(
                    "Expected finite probabilities with shape (1,15)"
                )
            values = tuple(
                ClassProbability(label=label, probability=float(probability))
                for label, probability in zip(self.contract.classes, raw[0], strict=True)
            )
            winner = int(np.argmax(raw[0]))
            result = NetworkThreatPrediction(
                predicted_class=self.contract.classes[winner],
                class_id=winner,
                confidence=float(raw[0, winner]),
                class_probabilities=values,
                threat_score=1.0 - float(raw[0, self.contract.benign_id]),
                model_name=self.model_name,
                model_version=self.model_version,
                deployment_profile=self.profile,
                feature_set_version=self.contract.feature_set_version,
                feature_contract_digest=self.contract.digest,
                label_mapping_digest=self.contract.label_mapping_digest,
                inference_latency_ms=latency,
            )
        except (NetworkArtifactError, SecurityAIOutputValidationError):
            self._log_failure(started)
            raise
        except ValueError as error:
            self._log_failure(started)
            raise SecurityAIOutputValidationError(
                "Invalid model probability output or artifact"
            ) from error
        except Exception as error:
            self._log_failure(started)
            raise SecurityAIInferenceError("Network model loading or inference failed") from error
        logger.info(
            "network_inference",
            extra={
                "backend": self.model_name,
                "version": self.model_version,
                "predicted_class": result.predicted_class,
                "confidence": result.confidence,
                "success": True,
                "inference_latency_ms": latency,
            },
        )
        return result

    def _log_failure(self, started: int) -> None:
        logger.warning(
            "network_inference_failed",
            extra={
                "backend": self.model_name,
                "version": self.model_version,
                "success": False,
                "inference_latency_ms": (time.perf_counter_ns() - started) / 1_000_000,
            },
        )


class LightGBMNetworkThreatPredictor(_Predictor):
    model_name = "network_cse2018_lightgbm_v4b2"
    model_version = "v4-b2"
    profile = DeploymentProfile.DETECTION_QUALITY

    def __init__(self, config: NetworkSecurityAIConfig, contract: Top40Contract) -> None:
        super().__init__(config, contract)
        self._model: Booster | None = None

    def _probabilities(self, matrix: np.ndarray) -> np.ndarray:
        if self._model is None:
            self._model = load_lightgbm(self.config, self.contract)
        # No scaler. Nonfinite values were normalized to NaN by the shared contract.
        return self._model.predict(matrix, num_threads=1)


class DNNNetworkThreatPredictor(_Predictor):
    model_name = "network_cse2018_dnn_fp32"
    model_version = "v4-fp32-epoch13"
    profile = DeploymentProfile.EDGE

    def __init__(self, config: NetworkSecurityAIConfig, contract: Top40Contract) -> None:
        super().__init__(config, contract)
        self._runtime: LoadedDNN | None = None

    def _probabilities(self, matrix: np.ndarray) -> np.ndarray:
        if self._runtime is None:
            self._runtime = load_dnn(self.config, self.contract)
        transformed = preprocess_dnn_batch(matrix, self._runtime.scaler)
        return self._runtime.probabilities(transformed)
