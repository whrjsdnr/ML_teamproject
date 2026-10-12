"""Minimal shared behavior; prediction schemas and score meanings stay model-specific."""

from collections.abc import Mapping
from typing import Protocol, runtime_checkable


@runtime_checkable
class SecurityAIPredictor[T_co](Protocol):
    def predict(self, features: Mapping[str, object]) -> T_co: ...
