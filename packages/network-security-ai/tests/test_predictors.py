import contextlib
import sys
from types import SimpleNamespace

import numpy as np
import pytest

from network_security_ai import NetworkArtifactError
from network_security_ai import predictors as module
from network_security_ai.errors import SecurityAIInferenceError, SecurityAIOutputValidationError


def test_lightgbm_native_loader_contract_and_cached_prediction(
    config, contract, features, booster, monkeypatch
):
    loads = []
    monkeypatch.setitem(
        sys.modules,
        "lightgbm",
        SimpleNamespace(Booster=lambda **kw: (loads.append(kw), booster)[1]),
    )
    p = module.LightGBMNetworkThreatPredictor(config, contract)
    features[contract.names[0]] = float("inf")
    for _ in range(2):
        r = p.predict(features)
        assert r.predicted_class == contract.classes[1] and r.class_id == 1
        assert r.confidence == 0.99 and r.inference_latency_ms >= 0
        assert r.threat_score == pytest.approx(1 - 0.01 / 14)
        assert r.deployment_profile == "detection_quality"
        assert len(r.class_probabilities) == 15 and r.inferred_at.tzinfo is not None
    assert len(loads) == 1
    assert np.isnan(booster.calls[0][0, 0])  # no scaler/imputation for LightGBM


@pytest.mark.parametrize("wrong", ["order", "count", "classes"])
def test_lightgbm_model_contract_mismatch(config, contract, booster, monkeypatch, wrong):
    if wrong == "order":
        booster.names = tuple(reversed(contract.names))
    elif wrong == "count":
        booster.num_feature = lambda: 39
    else:
        booster.num_model_per_iteration = lambda: 14
    monkeypatch.setitem(sys.modules, "lightgbm", SimpleNamespace(Booster=lambda **kw: booster))
    with pytest.raises(NetworkArtifactError):
        module.load_lightgbm(config, contract)


@pytest.mark.parametrize(
    "raw",
    [
        np.ones((1, 14)),
        np.ones((15,)),
        np.full((1, 15), np.nan),
        np.full((1, 15), -0.1),
        np.full((1, 15), 0.2),
    ],
)
def test_invalid_probabilities_never_produce_prediction(
    config, contract, features, booster, monkeypatch, raw
):
    booster.values = raw
    monkeypatch.setattr(module, "load_lightgbm", lambda *args: booster)
    with pytest.raises(SecurityAIOutputValidationError):
        module.LightGBMNetworkThreatPredictor(config, contract).predict(features)


def test_backend_runtime_failure_is_typed_and_not_raw_logged(
    config, contract, features, monkeypatch, caplog
):
    def fail(*args):
        raise RuntimeError("SECRET traffic content")

    monkeypatch.setattr(module, "load_lightgbm", fail)
    with pytest.raises(SecurityAIInferenceError, match="loading or inference failed"):
        module.LightGBMNetworkThreatPredictor(config, contract).predict(features)
    assert "SECRET" not in caplog.text
    assert caplog.records[-1].success is False


@pytest.mark.parametrize("field", ["lightgbm_path", "dnn_path", "scaler_path"])
def test_model_and_scaler_missing(config, contract, field):
    (config.artifact_root / getattr(config, field)).unlink()
    loader = module.load_lightgbm if field == "lightgbm_path" else module.load_dnn
    with pytest.raises(NetworkArtifactError):
        loader(config, contract)


def test_dnn_preprocess_uses_training_mean_no_fit_and_cache(
    config, contract, features, scaler, monkeypatch
):
    loads, inputs = [], []

    def probability(matrix):
        inputs.append(matrix.copy())
        values = np.zeros((1, 15))
        values[0, 0] = 1
        return values

    monkeypatch.setattr(
        module,
        "load_dnn",
        lambda *args: (
            loads.append(True),
            module.LoadedDNN(scaler=scaler, probabilities=probability),
        )[1],
    )
    p = module.DNNNetworkThreatPredictor(config, contract)
    features[contract.names[0]] = np.nan
    features[contract.names[1]] = np.inf
    features[contract.names[2]] = -np.inf
    for _ in range(2):
        r = p.predict(features)
        assert r.predicted_class == contract.classes[0] and r.class_id == 0
        assert r.threat_score == 0 and r.deployment_profile == "edge"
    assert len(loads) == 1 and len(scaler.captured) == 2
    np.testing.assert_array_equal(scaler.captured[0], np.arange(40).reshape(1, -1))
    np.testing.assert_array_equal(inputs[0], np.zeros((1, 40), dtype=np.float32))
    assert inputs[0].dtype == np.float32


def test_dnn_checkpoint_and_scaler_native_loader(config, contract, features, scaler, monkeypatch):
    calls = []

    class Model:
        def load_state_dict(self, weights, *, strict):
            calls.append(("weights", weights, strict))

        def eval(self):
            calls.append("eval")

        def __call__(self, matrix):
            assert matrix.dtype == np.float32
            result = np.zeros((1, 15))
            result[0, 2] = 1
            return SimpleNamespace(softmax=lambda dim: SimpleNamespace(numpy=lambda: result))

    def load(path, **kw):
        calls.append(("checkpoint", kw))
        return {"epoch": 13, "top40_features": list(contract.names), "model_state_dict": {}}

    monkeypatch.setitem(
        sys.modules,
        "torch",
        SimpleNamespace(
            load=load,
            inference_mode=contextlib.nullcontext,
            from_numpy=lambda x: x,
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "joblib",
        SimpleNamespace(load=lambda path: (calls.append("scaler"), scaler)[1]),
    )
    monkeypatch.setattr(module, "build_dnn", Model)
    p = module.DNNNetworkThreatPredictor(config, contract)
    assert p.predict(features).class_id == 2
    assert p.predict(features).class_id == 2
    assert calls == [
        ("checkpoint", {"map_location": "cpu", "weights_only": True}),
        "scaler",
        ("weights", {}, True),
        "eval",
    ]


@pytest.mark.parametrize(
    "bad", ["corrupt", "wrong_order", "wrong_epoch", "missing_weights", "bad_scaler"]
)
def test_dnn_invalid_checkpoint_is_typed(config, contract, features, scaler, monkeypatch, bad):
    def load(*args, **kw):
        if bad == "corrupt":
            raise RuntimeError("invalid checkpoint")
        return {
            "epoch": 12 if bad == "wrong_epoch" else 13,
            "top40_features": list(reversed(contract.names))
            if bad == "wrong_order"
            else list(contract.names),
        }

    if bad == "bad_scaler":
        scaler.mean_ = np.full(40, np.inf)
    monkeypatch.setitem(sys.modules, "torch", SimpleNamespace(load=load))
    monkeypatch.setitem(sys.modules, "joblib", SimpleNamespace(load=lambda path: scaler))
    monkeypatch.setattr(module, "build_dnn", lambda: SimpleNamespace())
    with pytest.raises(SecurityAIInferenceError):
        module.DNNNetworkThreatPredictor(config, contract).predict(features)
