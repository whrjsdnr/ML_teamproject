"""Prediction/evidence boundary tests without SOC imports or real model loading."""

import json
import sys
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from network_security_ai import (
    NetworkSecurityAIAdapter,
    NetworkSecurityEvidence,
    NetworkThreatPrediction,
    create_network_security_ai,
    prediction_to_evidence,
    predictors,
)
from network_security_ai.__main__ import main


def test_standalone_features_prediction_evidence(config, features, booster, monkeypatch):
    monkeypatch.setattr(predictors, "load_lightgbm", lambda *args: booster)
    adapter = create_network_security_ai(config)
    prediction = adapter.predict(dict(reversed(list(features.items()))))
    evidence = prediction_to_evidence(prediction, flow_reference="synthetic-flow-1")
    assert isinstance(prediction, NetworkThreatPrediction)
    assert isinstance(evidence, NetworkSecurityEvidence)
    assert evidence.prediction == prediction
    assert evidence.source == "network_security_ai"
    assert evidence.model_derived and not evidence.confidence_calibrated
    assert not evidence.attack_confirmed
    assert evidence.prediction.inference_latency_ms >= 0
    payload = evidence.model_dump(mode="json")
    assert not any(name in json.dumps(payload) for name in features)
    assert not any(name in payload for name in ("actions", "tools", "approval", "execution"))
    assert not any(hasattr(evidence, name) for name in ("execute", "block", "approve", "respond"))
    with pytest.raises(ValidationError):
        evidence.flow_reference = "changed"
    with pytest.raises(ValidationError):
        NetworkSecurityEvidence(prediction=prediction, action="firewall_block")
    with pytest.raises(ValidationError):
        NetworkSecurityEvidence(prediction=prediction, attack_confirmed=True)


def test_adapter_allows_fake_predictor_without_artifacts():
    expected = object()
    fake = Mock()
    fake.predict.return_value = expected
    adapter = NetworkSecurityAIAdapter(fake)
    assert adapter.predict({"test": 1}) is expected
    fake.predict.assert_called_once_with({"test": 1})


@pytest.mark.parametrize(
    "field,value",
    [
        ("class_id", 14),
        ("threat_score", 0),
        ("confidence", 0.5),
        ("inference_latency_ms", -1),
        ("inferred_at", "2026-10-06T12:00:00"),
        ("feature_contract_digest", "bad"),
        ("deployment_profile", "int8"),
    ],
)
def test_prediction_schema_rejects_inconsistent_output(
    config,
    contract,
    features,
    booster,
    monkeypatch,
    field,
    value,
):
    monkeypatch.setattr(predictors, "load_lightgbm", lambda *args: booster)
    p = predictors.LightGBMNetworkThreatPredictor(config, contract).predict(features)
    data = p.model_dump()
    data[field] = value
    with pytest.raises(ValidationError):
        NetworkThreatPrediction.model_validate(data)


def test_cli_standalone(config, contract, features, booster, monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(predictors, "load_lightgbm", lambda *args: booster)
    # CLI uses default manifest, inject fixture configuration to avoid real artifacts.
    import network_security_ai.__main__ as cli

    monkeypatch.setattr(cli, "NetworkSecurityAIConfig", lambda **kw: config)
    input_path = tmp_path / "input.json"
    input_path.write_text(json.dumps(features))
    monkeypatch.setattr(
        sys,
        "argv",
        ["network-security-ai", "--artifact-root", str(tmp_path), "--input", str(input_path)],
    )
    assert main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["prediction"]["predicted_class"] == contract.classes[1]
    assert payload["evidence"]["prediction"] == payload["prediction"]


def test_invalid_cli_input_is_failure(tmp_path, monkeypatch, capsys):
    path = tmp_path / "bad.json"
    path.write_text("[]")
    monkeypatch.setattr(
        sys, "argv", ["network-security-ai", "--artifact-root", str(tmp_path), "--input", str(path)]
    )
    assert main() == 1
    assert "failed" in capsys.readouterr().err


def test_missing_manifest_is_typed(config):
    from network_security_ai import NetworkArtifactError, Top40Contract

    (config.artifact_root / config.bundle_manifest_path).unlink()
    with pytest.raises(NetworkArtifactError):
        Top40Contract(config)


def test_repeated_adapter_inference_does_not_reread_metadata(
    config,
    contract,
    features,
    booster,
    monkeypatch,
):
    import network_security_ai.contracts as contracts

    monkeypatch.setattr(predictors, "load_lightgbm", lambda *args: booster)
    monkeypatch.setattr(predictors, "load_dnn", lambda *args: pytest.fail("unselected backend"))
    adapter = create_network_security_ai(config)
    monkeypatch.setattr(contracts.csv, "DictReader", lambda *args: pytest.fail("reread Top40"))
    monkeypatch.setattr(contracts.json, "loads", lambda *args: pytest.fail("reread mapping"))
    assert adapter.predict(features).class_id == 1
    assert adapter.predict(features).class_id == 1
