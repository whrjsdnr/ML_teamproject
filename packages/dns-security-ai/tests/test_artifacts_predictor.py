import hashlib
import sys
from types import SimpleNamespace

import numpy as np
import pytest
from pydantic import ValidationError

from dns_security_ai import DNSConfig, DNSPredictor, artifacts, predictor
from dns_security_ai.artifacts import manifest, verify_bundle
from dns_security_ai.cli import read_features
from dns_security_ai.errors import DNSArtifactError, DNSInputError, DNSOutputError
from dns_security_ai.preprocessing import dequantize_output


def test_detached_manifest():
    original = manifest()
    original["feature_names"].reverse()
    assert manifest()["feature_names"][0] == "FQDN_count"


def test_manifest_model_version(monkeypatch):
    import json

    altered = manifest()
    altered["model_version"] = "wrong-training-run"
    monkeypatch.setattr(artifacts, "_manifest_bytes", lambda: json.dumps(altered).encode())
    with pytest.raises(DNSArtifactError):
        manifest()


def test_missing_artifact(tmp_path, dns_features):
    p = DNSPredictor(DNSConfig(artifact_root=tmp_path))
    with pytest.raises(DNSArtifactError):
        p.predict(dns_features)
    assert p.metadata()["loaded"] is False


def test_corrupt_size_and_checksum_before_deserialization(tmp_path, monkeypatch):
    config = DNSConfig(artifact_root=tmp_path)
    model = tmp_path / config.model_path
    model.parent.mkdir()
    model.write_bytes(b"bad")
    with pytest.raises(DNSArtifactError, match="size"):
        verify_bundle(config)
    model.write_bytes(b"x" * manifest()["artifacts"]["model_path"]["size_bytes"])
    monkeypatch.setitem(sys.modules, "joblib", SimpleNamespace(load=lambda _: pytest.fail("load")))
    with pytest.raises(DNSArtifactError, match="checksum"):
        predictor.load_runtime(config)


def test_verified_bundle_and_mixed_scaler(tmp_path, monkeypatch):
    entries = {}
    for field, filename in (
        ("model_path", "model/dnn_int8.tflite"),
        ("scaler_path", "preprocessor/scaler.joblib"),
    ):
        path = tmp_path / filename
        path.parent.mkdir()
        value = field.encode()
        path.write_bytes(value)
        entries[field] = {"size_bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
    monkeypatch.setattr(artifacts, "manifest", lambda: {"artifacts": entries})
    assert len(verify_bundle(DNSConfig(artifact_root=tmp_path))) == 2
    (tmp_path / "preprocessor/scaler.joblib").write_bytes(
        b"x" * entries["scaler_path"]["size_bytes"]
    )
    with pytest.raises(DNSArtifactError, match="checksum"):
        verify_bundle(DNSConfig(artifact_root=tmp_path))


def test_symlink_escape(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.write_bytes(b"x")
    (tmp_path / "escape").symlink_to(outside)
    with pytest.raises(DNSArtifactError):
        DNSConfig(artifact_root=tmp_path).artifact(tmp_path / "escape")


def test_invalid_input_does_not_load_model(tmp_path, monkeypatch):
    monkeypatch.setattr(predictor, "load_runtime", lambda _: pytest.fail("model loaded"))
    with pytest.raises(DNSInputError):
        DNSPredictor(DNSConfig(artifact_root=tmp_path)).predict({})


def test_copied_config_is_revalidated(tmp_path):
    invalid = DNSConfig(artifact_root=tmp_path).model_copy(update={"model_path": "../escape"})
    with pytest.raises(ValidationError):
        DNSPredictor(invalid)


def test_lazy_cache_and_prediction(tmp_path, dns_features, monkeypatch):
    calls = []

    class Interpreter:
        def set_tensor(self, index, matrix):
            assert matrix.shape == (1, 9)

        def invoke(self):
            pass

        def get_tensor(self, index):
            return np.array([[64]], dtype=np.int8)

    loaded = predictor.LoadedDNS(None, Interpreter(), 0, 1, 1, 0, 1 / 256, -128)
    monkeypatch.setattr(predictor, "load_runtime", lambda _: calls.append(1) or loaded)
    monkeypatch.setattr(predictor, "quantize_input", lambda m, *args: m.astype(np.int8))
    p = DNSPredictor(DNSConfig(artifact_root=tmp_path))
    assert p.metadata()["loaded"] is False
    for _ in range(2):
        result = p.predict(dns_features)
        assert (result.label, result.class_id, result.probability) == ("MALICIOUS", 1, 0.75)
    assert calls == [1]


@pytest.mark.parametrize("output", [np.array([[1.0]]), np.ones((1, 2), dtype=np.int8)])
def test_invalid_output_shape_dtype(output):
    with pytest.raises(DNSOutputError):
        dequantize_output(output, 1 / 256, -128)


def test_invalid_output_semantics():
    with pytest.raises(DNSOutputError):
        dequantize_output(np.array([[127]], dtype=np.int8), 1, -128)
    with pytest.raises(DNSArtifactError):
        dequantize_output(np.array([[0]], dtype=np.int8), 0, -128)


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b"[]", b"x" * 65537, b"{"])
def test_bounded_json(tmp_path, raw):
    path = tmp_path / "input.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        read_features(path)
