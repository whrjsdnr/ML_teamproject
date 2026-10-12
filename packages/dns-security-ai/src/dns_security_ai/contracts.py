"""Contract order confirmed against legacy detector, notebook and fitted scaler."""

import hashlib
import math
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, Self

import numpy as np
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from dns_security_ai.errors import DNSArtifactError, DNSInputError

FEATURE_NAMES = (
    "FQDN_count",
    "subdomain_length",
    "numeric",
    "entropy",
    "special",
    "labels",
    "labels_max",
    "labels_average",
    "len",
)
FEATURE_VERSION = "cic-bell-dns-stateless9-v1"
FEATURE_DIGEST = hashlib.sha256("\n".join(FEATURE_NAMES).encode()).hexdigest()
MODEL_ID = "dns_cicbell_dnn_int8"
# Content identity, not an invented training revision.
MODEL_VERSION = "int8-sha256-28e089af363d"
Text = Annotated[str, Field(min_length=1, max_length=256)]
Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


def utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Timestamp must be timezone-aware")
    return value.astimezone(UTC)


Timestamp = Annotated[datetime, AfterValidator(utc)]


class Snapshot(BaseModel):
    model_config = ConfigDict(
        frozen=True, extra="forbid", validate_default=True, revalidate_instances="always"
    )


class DNSConfig(Snapshot):
    """Administrator-controlled root; never accept artifact paths from DNS input."""

    artifact_root: Path
    model_path: Path = Path("model/dnn_int8.tflite")
    scaler_path: Path = Path("preprocessor/scaler.joblib")
    runtime: Literal["litert", "tensorflow"] = "litert"
    # No inference-time threshold tuning; retain the supplied detector default.
    threshold: Literal[0.5] = 0.5

    @field_validator("model_path", "scaler_path")
    @classmethod
    def relative(cls, value: Path) -> Path:
        if value.is_absolute() or ".." in value.parts:
            raise ValueError("Artifact paths must be relative and contained")
        return value

    def artifact(self, value: Path) -> Path:
        root = self.artifact_root.resolve()
        path = (root / value).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise DNSArtifactError("Artifact is missing or outside the trusted root")
        return path


class DNSFeatureContract:
    names = FEATURE_NAMES
    schema_version = FEATURE_VERSION
    digest = FEATURE_DIGEST

    def matrix(self, features: Mapping[str, object]) -> np.ndarray:
        if not isinstance(features, Mapping) or len(features) != 9:
            raise DNSInputError("Expected exactly nine named numeric features")
        if set(features) != set(self.names):
            raise DNSInputError("Feature keys differ from the DNS contract")
        values = []
        for name in self.names:
            raw = features[name]
            if isinstance(raw, (bool, np.bool_)) or not isinstance(
                raw, (int, float, np.integer, np.floating)
            ):
                raise DNSInputError("DNS features must be numeric scalars")
            try:
                value = float(raw)
            except (ValueError, TypeError, OverflowError) as error:
                raise DNSInputError("Invalid DNS numeric value") from error
            # No imputer or missing policy exists in the supplied DNS implementation.
            if not math.isfinite(value) or value < 0 or value > float(np.finfo(np.float32).max):
                raise DNSInputError("DNS features must be finite nonnegative float32 values")
            values.append(value)
        return np.array([values], dtype=np.float32)


class DNSArtifactReference(Snapshot):
    bundle_version: Literal["dns-int8-reviewed-1"] = "dns-int8-reviewed-1"
    model_sha256: Digest
    scaler_sha256: Digest
    feature_contract_digest: Literal[FEATURE_DIGEST] = FEATURE_DIGEST


class DNSThreatPrediction(Snapshot):
    prediction_type: Literal["binary_classification"] = "binary_classification"
    class_id: Literal[0, 1]
    label: Literal["NORMAL", "MALICIOUS"]
    probability: float = Field(ge=0, le=1, allow_inf_nan=False)
    score_type: Literal["uncalibrated_malicious_probability"] = "uncalibrated_malicious_probability"
    threshold: Literal[0.5] = 0.5
    confidence_calibrated: Literal[False] = False
    model_id: Literal[MODEL_ID] = MODEL_ID
    model_version: Literal[MODEL_VERSION] = MODEL_VERSION
    feature_schema_version: Literal[FEATURE_VERSION] = FEATURE_VERSION
    runtime: Literal["litert", "tensorflow"]
    artifacts: DNSArtifactReference
    inferred_at: Timestamp = Field(default_factory=lambda: datetime.now(UTC))
    inference_latency_ms: float = Field(ge=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def semantics(self) -> Self:
        from dns_security_ai.artifacts import manifest

        expected = int(self.probability >= self.threshold)
        if self.class_id != expected or self.label != ("NORMAL", "MALICIOUS")[expected]:
            raise ValueError("Label and class ID must agree with the fixed threshold")
        bundle = manifest()
        if (
            self.artifacts.model_sha256 != bundle["artifacts"]["model_path"]["sha256"]
            or self.artifacts.scaler_sha256 != bundle["artifacts"]["scaler_path"]["sha256"]
        ):
            raise ValueError("Prediction artifact provenance differs from the reviewed bundle")
        return self
