"""Network-only immutable data schemas; no SOC or DNS assumptions."""

import math
from datetime import UTC, datetime
from typing import Annotated, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

NonEmptyText = Annotated[str, Field(min_length=1, max_length=256)]


def utc_now() -> datetime:
    return datetime.now(UTC)


def require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Timestamp must be timezone-aware")
    return value.astimezone(UTC)


UTCTimestamp = Annotated[datetime, AfterValidator(require_utc)]


class Snapshot(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", validate_default=True)


class ClassProbability(Snapshot):
    label: NonEmptyText
    probability: float = Field(ge=0, le=1, allow_inf_nan=False)


class ClassificationPrediction(Snapshot):
    predicted_class: NonEmptyText
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    class_probabilities: tuple[ClassProbability, ...]

    @model_validator(mode="after")
    def validate_probabilities(self) -> Self:
        values = self.class_probabilities
        if not values or len({p.label for p in values}) != len(values):
            raise ValueError("Invalid probability labels")
        if not math.isclose(sum(p.probability for p in values), 1, abs_tol=1e-5):
            raise ValueError("Probabilities must sum to one")
        winner = max(values, key=lambda p: p.probability)
        if (self.predicted_class, self.confidence) != (winner.label, winner.probability):
            raise ValueError("Prediction differs from probability maximum")
        return self
