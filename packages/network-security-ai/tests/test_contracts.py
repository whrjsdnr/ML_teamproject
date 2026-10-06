import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np
import pytest
from pydantic import ValidationError

from network_security_ai import (
    NetworkArtifactError,
    NetworkSecurityAIConfig,
    Top40Contract,
    create_network_security_ai,
)
from network_security_ai.errors import SecurityAIInputValidationError
from network_security_ai.predictors import LightGBMNetworkThreatPredictor


def test_reordered_features_are_canonical_float32(contract, features):
    shuffled = dict(reversed(list(features.items())))
    shuffled[contract.names[0]] = "12.5"
    matrix = contract.matrix(shuffled)
    assert matrix.dtype == np.float32 and matrix.shape == (1, 40)
    assert matrix[0, 0] == 12.5
    assert matrix[0, 1:].tolist() == list(range(1, 40))


@pytest.mark.parametrize(
    "bad", ["not-a-number", True, np.bool_(True), np.array([1]), [], {}, complex(1, 2), 1e100]
)
def test_nonnumeric_and_overflow_rejected(contract, features, bad):
    features[contract.names[0]] = bad
    with pytest.raises(SecurityAIInputValidationError):
        contract.matrix(features)


@pytest.mark.parametrize(
    "nonfinite", [None, float("nan"), float("inf"), -float("inf"), "NaN", "Infinity"]
)
def test_nonfinite_becomes_explicit_missing(contract, features, nonfinite):
    features[contract.names[0]] = nonfinite
    assert np.isnan(contract.matrix(features)[0, 0])
    assert contract.payload(features)[contract.names[0]] is None
    assert "NaN" not in json.dumps(contract.payload(features), allow_nan=False)


@pytest.mark.parametrize("kind", ["missing", "extra"])
def test_exact_feature_keys(contract, features, kind):
    if kind == "missing":
        features.pop(contract.names[0])
    else:
        features["Label"] = "Benign"
    with pytest.raises(SecurityAIInputValidationError):
        contract.matrix(features)


@pytest.mark.parametrize(
    "profile,backend",
    [
        ("detection_quality", "LightGBMNetworkThreatPredictor"),
        ("edge", "DNNNetworkThreatPredictor"),
    ],
)
def test_profile_factory_is_lazy(config, profile, backend, monkeypatch):
    import network_security_ai.predictors as module

    monkeypatch.setattr(module, "load_lightgbm", lambda *args: pytest.fail("not lazy"))
    monkeypatch.setattr(module, "load_dnn", lambda *args: pytest.fail("not lazy"))
    adapter = create_network_security_ai(
        NetworkSecurityAIConfig.model_validate({**config.model_dump(), "profile": profile})
    )
    assert type(adapter.predictor).__name__ == backend


def test_disabled_does_no_artifact_io(tmp_path):
    config = NetworkSecurityAIConfig(artifact_root=tmp_path / "missing")
    assert create_network_security_ai(config) is None


def test_invalid_profile_and_path_fail_validation(tmp_path):
    with pytest.raises(ValidationError):
        NetworkSecurityAIConfig(artifact_root=tmp_path, profile="int8")
    for path in ("../model", "/etc/passwd"):
        with pytest.raises(ValidationError):
            NetworkSecurityAIConfig(artifact_root=tmp_path, dnn_path=path)


@pytest.mark.parametrize("field", ["top40_path", "label_mapping_path"])
def test_missing_contract_artifact_is_typed(config, field):
    getattr(config, field)  # supplied relative artifact
    (config.artifact_root / getattr(config, field)).unlink()
    with pytest.raises(NetworkArtifactError):
        Top40Contract(config)


@pytest.mark.parametrize(
    "mapping", [{"Benign": 0}, {str(i): i for i in range(15)}, {"Benign": True}]
)
def test_invalid_mapping_fails(config, mapping):
    (config.artifact_root / config.label_mapping_path).write_text(json.dumps(mapping))
    with pytest.raises(NetworkArtifactError):
        Top40Contract(config)


def test_bad_top40_order_and_duplicates_fail(config):
    path = config.artifact_root / config.top40_path
    path.write_text("rank,feature\n" + "\n".join(f"{i},same" for i in range(1, 41)))
    with pytest.raises(NetworkArtifactError):
        Top40Contract(config)


def test_symlink_escape_rejected(config, tmp_path):
    external = tmp_path.parent / (tmp_path.name + "-outside")
    external.write_text("not an artifact")
    path = config.artifact_root / config.lightgbm_path
    path.unlink()
    path.symlink_to(external)
    with pytest.raises(NetworkArtifactError):
        config.artifact(config.lightgbm_path)


def test_concurrent_first_use_loads_once(config, contract, features, booster, monkeypatch):
    import network_security_ai.predictors as module

    loads = []
    monkeypatch.setattr(module, "load_lightgbm", lambda *args: (loads.append(True), booster)[1])
    predictor = LightGBMNetworkThreatPredictor(config, contract)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(predictor.predict, [features] * 8))
    assert len(loads) == 1 and len(results) == 8
    assert len(booster.calls) == 8


def test_no_optional_runtime_import_in_new_process():
    import subprocess

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import network_security_ai; "
            "assert 'torch' not in sys.modules; assert 'lightgbm' not in sys.modules; "
            "assert 'torchao' not in sys.modules; assert 'soc_agent' not in sys.modules",
        ],
        env=dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src")),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("field", ["lightgbm_path", "dnn_path", "scaler_path"])
def test_unreviewed_artifact_fails_before_loading(config, contract, field):
    path = config.artifact_root / getattr(config, field)
    path.write_bytes(b"different artifact, same declared profile")
    with pytest.raises(NetworkArtifactError, match="checksum differs"):
        contract.verify_artifact(config, field)
