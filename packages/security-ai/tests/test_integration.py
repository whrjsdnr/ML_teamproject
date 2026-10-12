import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest
from dns_security_ai import DNSConfig, DNSPredictor
from dns_security_ai import predictor as dns_backend
from dns_security_ai.evidence import prediction_to_evidence as dns_evidence
from network_security_ai import (
    NetworkSecurityAIConfig,
    create_network_security_ai,
)
from network_security_ai import (
    prediction_to_evidence as network_evidence,
)
from network_security_ai import predictors as network_backend
from network_security_ai.errors import SecurityAIInferenceError
from pydantic import ValidationError

from security_ai import EvidenceEnvelope, SecurityAIPredictor, to_envelope
from security_ai.network import NetworkSecurityAIConfig as ReexportedConfig


@pytest.fixture
def models(tmp_path, monkeypatch):
    class Booster:
        def predict(self, matrix, **kwargs):
            values = np.zeros((1, 15))
            values[0, 0] = 1
            return values

    monkeypatch.setattr(network_backend, "load_lightgbm", lambda *_: Booster())

    class Interpreter:
        def set_tensor(self, *_):
            pass

        def invoke(self):
            pass

        def get_tensor(self, *_):
            return np.array([[64]], dtype=np.int8)

    runtime = dns_backend.LoadedDNS(None, Interpreter(), 0, 1, 1, 0, 1 / 256, -128)
    monkeypatch.setattr(dns_backend, "load_runtime", lambda _: runtime)
    monkeypatch.setattr(dns_backend, "quantize_input", lambda m, *_: m.astype(np.int8))
    n = create_network_security_ai(NetworkSecurityAIConfig(enabled=True, artifact_root=tmp_path))
    d = DNSPredictor(DNSConfig(artifact_root=tmp_path))
    return n, d


def network_features(network):
    return dict.fromkeys(network.predictor.contract.names, 0)


def dns_features(dns):
    return dict.fromkeys(dns.contract.names, 0)


def test_existing_network_api_is_canonical():
    assert ReexportedConfig is NetworkSecurityAIConfig


def test_sequential_independent_inputs_and_typed_payloads(models):
    n, d = models
    assert isinstance(n, SecurityAIPredictor)
    assert isinstance(d, SecurityAIPredictor)
    ne = network_evidence(n.predict(network_features(n)), flow_reference="flow-ref")
    de = dns_evidence(d.predict(dns_features(d)), observation_ref="dns-ref")
    network, dns = to_envelope(ne), to_envelope(de)
    assert network.source != dns.source
    assert network.evidence_id != dns.evidence_id
    assert dns.evidence_id == de.evidence_id
    assert (
        network.payload.prediction.threat_score
        == 1 - ne.prediction.class_probabilities[0].probability
    )
    assert dns.payload.prediction.probability == 0.75
    assert network.observation_ref == "flow-ref"
    assert dns.observation_ref == "dns-ref"
    for item in (network, dns):
        assert EvidenceEnvelope.model_validate_json(item.model_dump_json()) == item
        with pytest.raises(ValidationError):
            item.model_version = "modified"


@pytest.mark.parametrize(
    "field,value",
    [
        ("source", "network_security_ai"),
        ("model_id", "wrong-model"),
        ("model_version", "wrong-version"),
        ("observation_ref", "invented-reference"),
        ("evidence_type", "network_threat_prediction"),
        ("unexpected", "raw-payload"),
        ("timestamp", "2026-10-12T12:00:00Z"),
    ],
)
def test_malformed_envelope_provenance(models, field, value):
    _, d = models
    data = to_envelope(dns_evidence(d.predict(dns_features(d)))).model_dump()
    data[field] = value
    with pytest.raises(ValidationError):
        EvidenceEnvelope.model_validate(data)


def test_network_copied_payload_revalidated(models):
    n, _ = models
    ne = network_evidence(n.predict(network_features(n)))
    tampered = ne.model_copy(
        update={"prediction": ne.prediction.model_copy(update={"confidence": 2})}
    )
    with pytest.raises(ValidationError):
        to_envelope(tampered)


def test_dns_failure_leaves_network_operational(models, monkeypatch):
    n, d = models
    monkeypatch.setattr(
        dns_backend, "load_runtime", lambda _: (_ for _ in ()).throw(RuntimeError("failed"))
    )
    from dns_security_ai.errors import DNSInferenceError

    with pytest.raises(DNSInferenceError):
        d.predict(dns_features(d))
    assert n.predict(network_features(n)).class_id == 0


def test_network_failure_leaves_dns_operational(models, monkeypatch):
    n, d = models
    monkeypatch.setattr(
        network_backend, "load_lightgbm", lambda *_: (_ for _ in ()).throw(RuntimeError("failed"))
    )
    with pytest.raises(SecurityAIInferenceError):
        n.predict(network_features(n))
    assert d.predict(dns_features(d)).class_id == 1


def test_unselected_backends_stay_unloaded(models):
    n, d = models
    n.predict(network_features(n))
    assert d.metadata()["loaded"] is False


def test_import_without_heavy_dependencies_or_soc():
    # A fresh process rejects every optional runtime import even when installed.
    code = """
import importlib.abc, sys
class Reject(importlib.abc.MetaPathFinder):
    def find_spec(self, name, *args):
        if name.split('.')[0] in {
            'soc_agent','tensorflow','torch','lightgbm','sklearn','joblib','pandas','ai_edge_litert'
        }:
            raise RuntimeError('unexpected import: '+name)
sys.meta_path.insert(0, Reject())
import security_ai, dns_security_ai, network_security_ai
from dns_security_ai import DNSConfig, DNSPredictor
p = DNSPredictor(DNSConfig(artifact_root='/tmp/artifacts-not-required-for-import'))
assert p.metadata()['loaded'] is False
"""
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_cli_failure_isolated_and_sanitized(tmp_path):
    path = tmp_path / "features.json"
    path.write_text(json.dumps({"secret-domain": "private"}))
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "security_ai",
            "dns",
            "--artifact-root",
            str(tmp_path),
            "--input",
            str(path),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "private" not in result.stderr
    assert "secret-domain" not in result.stderr
    assert not result.stdout


def test_foreign_source_not_accepted():
    with pytest.raises(TypeError):
        to_envelope({"source": "other"})


def test_package_tree_has_no_soc_source_dependencies():
    root = Path(__file__).parents[1] / "src"
    assert all("from soc_agent" not in p.read_text() for p in root.rglob("*.py"))
