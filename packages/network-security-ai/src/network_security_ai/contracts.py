"""CSE-CIC-IDS2018 Top40 artifacts and bounded, ordered input contract."""

import csv
import hashlib
import json
import math
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Protocol, Self

import numpy as np
from pydantic import Field, field_validator, model_validator

from network_security_ai.errors import SecurityAIInferenceError, SecurityAIInputValidationError
from network_security_ai.schema import (
    ClassificationPrediction,
    NonEmptyText,
    Snapshot,
    UTCTimestamp,
    utc_now,
)


class NetworkArtifactError(SecurityAIInferenceError):
    """Missing, corrupt, incompatible or untrusted configured artifact."""


class DeploymentProfile(StrEnum):
    DETECTION_QUALITY = "detection_quality"
    EDGE = "edge"


class NetworkSecurityAIConfig(Snapshot):
    """Trusted composition settings; artifact paths are relative to an explicit root.

    Root files must be administrator-controlled. joblib/scaler loading is not safe
    for untrusted pickle artifacts. No path is obtained from an inference request.
    """

    enabled: bool = False
    profile: DeploymentProfile = DeploymentProfile.DETECTION_QUALITY
    artifact_root: Path
    top40_path: Path = Path("results/feature_selection/top40_features.csv")
    label_mapping_path: Path = Path("data/processed/network_ml/label_mapping.json")
    lightgbm_path: Path = Path("models/network/lightgbm_top40_v4b2.txt")
    dnn_path: Path = Path("models/network/dnn_top40_v4_best.pt")
    scaler_path: Path = Path("models/network/dnn_top40_v4_scaler.joblib")
    bundle_manifest_path: Path | None = None

    @field_validator("top40_path", "label_mapping_path", "lightgbm_path", "dnn_path", "scaler_path")
    @classmethod
    def relative_artifact(cls, value: Path) -> Path:
        if value.is_absolute() or ".." in value.parts:
            raise ValueError("Artifact paths must be contained project-relative paths")
        return value

    @field_validator("bundle_manifest_path")
    @classmethod
    def relative_manifest(cls, value: Path | None) -> Path | None:
        return None if value is None else cls.relative_artifact(value)

    def artifact(self, path: Path) -> Path:
        root = self.artifact_root.resolve()
        resolved = (root / path).resolve()
        if not resolved.is_relative_to(root) or not resolved.is_file():
            raise NetworkArtifactError("Configured artifact is missing or outside its root")
        return resolved


class NetworkThreatPrediction(ClassificationPrediction):
    """Raw model probabilities, not calibrated risk or action authorization."""

    class_id: int = Field(ge=0, lt=15)
    threat_score: float = Field(ge=0, le=1, allow_inf_nan=False)
    model_name: NonEmptyText
    model_version: NonEmptyText
    deployment_profile: DeploymentProfile
    feature_set_version: NonEmptyText
    feature_contract_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    label_mapping_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    inferred_at: UTCTimestamp = Field(default_factory=utc_now)
    inference_latency_ms: float = Field(ge=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def validate_network_identity(self) -> Self:
        if len(self.class_probabilities) != 15:
            raise ValueError("Network output requires 15 classes")
        if self.class_probabilities[self.class_id].label != self.predicted_class:
            raise ValueError("Class ID differs from the winning probability column")
        benign = next((p for p in self.class_probabilities if p.label == "Benign"), None)
        if benign is None or not math.isclose(
            self.threat_score, 1 - benign.probability, abs_tol=1e-7
        ):
            raise ValueError("Threat score must equal 1 - P(Benign)")
        return self


class NetworkThreatPredictor(Protocol):
    contract: "Top40Contract"
    model_name: str
    model_version: str
    profile: DeploymentProfile

    def predict(self, features: Mapping[str, object]) -> NetworkThreatPrediction: ...


class Top40Contract:
    """Read immutable feature order/mapping once. No model/scaler import or loading."""

    def __init__(self, config: NetworkSecurityAIConfig) -> None:
        try:
            manifest_path = (
                config.artifact(config.bundle_manifest_path)
                if config.bundle_manifest_path is not None
                else Path(__file__).with_name("artifact_manifest.json")
            )
            manifest = json.loads(manifest_path.read_bytes())
            self.artifact_digests = dict(manifest["sha256"])
            required = {
                "top40_path",
                "label_mapping_path",
                "lightgbm_path",
                "dnn_path",
                "scaler_path",
            }
            if set(self.artifact_digests) != required or not all(
                isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v)
                for v in self.artifact_digests.values()
            ):
                raise ValueError("Invalid bundle digest manifest")
            self.verify_artifact(config, "top40_path")
            self.verify_artifact(config, "label_mapping_path")
            with config.artifact(config.top40_path).open(newline="", encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream))
            if len(rows) != 40 or [int(r["rank"]) for r in rows] != list(range(1, 41)):
                raise ValueError("Expected ordered ranks 1..40")
            self.names = tuple(r["feature"] for r in rows)
            if len(set(self.names)) != 40 or not all(self.names):
                raise ValueError("Invalid Top40 names")
            content = config.artifact(config.label_mapping_path).read_bytes()
            mapping = json.loads(content)
            if (
                not isinstance(mapping, dict)
                or len(mapping) != 15
                or not all(isinstance(k, str) and k.strip() for k in mapping)
                or not all(type(v) is int for v in mapping.values())
                or set(mapping.values()) != set(range(15))
                or "Benign" not in mapping
            ):
                raise ValueError("Expected 15 contiguous class IDs and a Benign label")
            self.classes = tuple(sorted(mapping, key=mapping.__getitem__))
            self.benign_id = mapping["Benign"]
            self.label_mapping_digest = hashlib.sha256(content).hexdigest()
            self.digest = hashlib.sha256("\n".join(self.names).encode()).hexdigest()
            self.feature_set_version = "cse-cic-ids2018-top40-v1"

        except NetworkArtifactError:
            raise
        except (OSError, ValueError, TypeError, KeyError) as error:
            raise NetworkArtifactError("Invalid Top40 or label mapping artifact") from error

    def verify_artifact(self, config: NetworkSecurityAIConfig, field: str) -> Path:
        path = config.artifact(getattr(config, field))
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != self.artifact_digests[field]:
            raise NetworkArtifactError("Artifact checksum differs from trusted model bundle")
        return path

    def matrix(self, features: Mapping[str, object]) -> np.ndarray:
        if set(features) != set(self.names):
            raise SecurityAIInputValidationError("Feature keys must match the Top40 contract")
        values = []
        try:
            for name in self.names:
                raw = features[name]
                if isinstance(raw, (bool, np.bool_, np.ndarray, list, dict, tuple)):
                    raise ValueError("Expected numeric scalar")
                value = math.nan if raw is None else float(raw)
                if not math.isfinite(value):
                    value = math.nan
                elif abs(value) > float(np.finfo(np.float32).max):
                    raise ValueError("Value cannot be represented as float32")
                values.append(value)
        except (ValueError, TypeError, OverflowError) as error:
            raise SecurityAIInputValidationError(
                "Feature values must be numeric float32 scalars"
            ) from error
        return np.array([values], dtype=np.float32)

    def payload(self, features: Mapping[str, object]) -> dict[str, float | None]:
        values = self.matrix(features)[0]
        return {
            n: None if np.isnan(v) else float(v) for n, v in zip(self.names, values, strict=True)
        }
