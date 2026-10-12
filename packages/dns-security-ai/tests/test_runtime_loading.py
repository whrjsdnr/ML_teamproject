import sys
from types import SimpleNamespace

import numpy as np
import pytest

from dns_security_ai import DNSConfig, predictor
from dns_security_ai.artifacts import manifest
from dns_security_ai.errors import DNSArtifactError, DNSInferenceError


def install_fake_runtime(monkeypatch, change=None):
    class Interpreter:
        def __init__(self, **kwargs):
            pass

        def allocate_tensors(self):
            pass

        def detail(self, name, index):
            v = manifest()["tensors"][name]
            result = dict(
                shape=np.array(v["shape"]),
                dtype=np.int8,
                index=index,
                quantization=v["quantization"],
                quantization_parameters={"scales": [1], "zero_points": [0]},
            )
            if change and name == "input":
                result.update(change)
            return result

        def get_input_details(self):
            return [self.detail("input", 0)]

        def get_output_details(self):
            return [self.detail("output", 1)]

    monkeypatch.setitem(sys.modules, "joblib", SimpleNamespace(load=lambda _: object()))
    monkeypatch.setitem(
        sys.modules, "ai_edge_litert.interpreter", SimpleNamespace(Interpreter=Interpreter)
    )
    monkeypatch.setattr(
        predictor, "verify_bundle", lambda _: {"scaler_path": "scaler", "model_path": "model"}
    )
    monkeypatch.setattr(predictor, "validate_scaler", lambda _: None)


def test_load_runtime_contract(tmp_path, monkeypatch):
    install_fake_runtime(monkeypatch)
    loaded = predictor.load_runtime(DNSConfig(artifact_root=tmp_path))
    assert loaded.input_scale == 0.0387900173664093
    assert loaded.output_scale == 1 / 256


@pytest.mark.parametrize(
    "change",
    [
        {"shape": [1, 8]},
        {"dtype": np.float32},
        {"quantization": (0, 0)},
        {"quantization_parameters": {"scales": [1, 2], "zero_points": [0, 1]}},
    ],
)
def test_reject_incompatible_tensor(tmp_path, monkeypatch, change):
    install_fake_runtime(monkeypatch, change)
    with pytest.raises(DNSArtifactError):
        predictor.load_runtime(DNSConfig(artifact_root=tmp_path))


def test_missing_optional_dependency(tmp_path, monkeypatch):
    install_fake_runtime(monkeypatch)
    monkeypatch.setitem(sys.modules, "ai_edge_litert.interpreter", None)
    with pytest.raises(DNSInferenceError, match="runtime extra"):
        predictor.load_runtime(DNSConfig(artifact_root=tmp_path))
