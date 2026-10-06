import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

from network_security_ai import NetworkSecurityAIConfig, Top40Contract


@pytest.fixture
def config(tmp_path):
    fixture = Path(__file__).parent / "fixtures"
    for name in ("top40_features.csv", "label_mapping.json"):
        (tmp_path / name).write_bytes((fixture / name).read_bytes())
    for name in ("model.txt", "model.pt", "scaler.joblib"):
        (tmp_path / name).touch()
    digests = {
        "top40_path": "top40_features.csv",
        "label_mapping_path": "label_mapping.json",
        "lightgbm_path": "model.txt",
        "dnn_path": "model.pt",
        "scaler_path": "scaler.joblib",
    }
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "sha256": {
                    field: hashlib.sha256((tmp_path / path).read_bytes()).hexdigest()
                    for field, path in digests.items()
                }
            }
        )
    )
    return NetworkSecurityAIConfig(
        bundle_manifest_path="manifest.json",
        enabled=True,
        artifact_root=tmp_path,
        top40_path="top40_features.csv",
        label_mapping_path="label_mapping.json",
        lightgbm_path="model.txt",
        dnn_path="model.pt",
        scaler_path="scaler.joblib",
    )


@pytest.fixture
def contract(config):
    return Top40Contract(config)


@pytest.fixture
def features(contract):
    return {n: float(i) for i, n in enumerate(contract.names)}


class FakeBooster:
    def __init__(self, names, winner=1):
        self.names = names
        self.values = np.full((1, 15), 0.01 / 14)
        self.values[0, winner] = 0.99
        self.calls = []

    def feature_name(self):
        return [n.replace(" ", "_") for n in self.names]

    def num_feature(self):
        return 40

    def num_model_per_iteration(self):
        return 15

    def predict(self, matrix, *, num_threads):
        assert num_threads == 1
        self.calls.append(matrix.copy())
        return self.values.copy()


@pytest.fixture
def booster(contract):
    return FakeBooster(contract.names)


@pytest.fixture
def scaler():
    captured = []

    def transform(matrix):
        captured.append(matrix.copy())
        return (matrix - np.arange(40)) / 2

    return SimpleNamespace(
        n_features_in_=40,
        mean_=np.arange(40, dtype=float),
        scale_=np.full(40, 2.0),
        transform=transform,
        captured=captured,
    )
