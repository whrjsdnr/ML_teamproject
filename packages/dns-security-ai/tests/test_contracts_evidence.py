import math

import numpy as np
import pytest
from pydantic import ValidationError

from dns_security_ai import DNSConfig, DNSFeatureContract, DNSThreatPrediction
from dns_security_ai.errors import DNSInputError
from dns_security_ai.evidence import prediction_to_evidence


def test_order_is_explicit(dns_features):
    ordered = DNSFeatureContract().matrix(dict(reversed(list(dns_features.items()))))
    np.testing.assert_array_equal(
        ordered, np.array([list(dns_features.values())], dtype=np.float32)
    )
    assert ordered.shape == (1, 9)
    assert DNSFeatureContract.names == (
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


@pytest.mark.parametrize(
    "bad", [None, True, "3", [], {}, [1], math.nan, math.inf, -math.inf, -1, 1e100, 10**1000]
)
def test_invalid_scalars(dns_features, bad):
    dns_features["entropy"] = bad
    with pytest.raises(DNSInputError):
        DNSFeatureContract().matrix(dns_features)


@pytest.mark.parametrize("value", [None, [], {}, {str(i): 1 for i in range(10000)}])
def test_invalid_shape(value):
    with pytest.raises(DNSInputError):
        DNSFeatureContract().matrix(value)


def test_unknown_and_missing_keys(dns_features):
    dns_features["unknown"] = dns_features.pop("len")
    with pytest.raises(DNSInputError):
        DNSFeatureContract().matrix(dns_features)


@pytest.mark.parametrize(
    "field,value",
    [
        ("probability", math.nan),
        ("probability", 1.1),
        ("probability", -0.1),
        ("class_id", 0),
        ("label", "NORMAL"),
        ("threshold", 0.4),
        ("score_type", "anomaly_score"),
        ("model_version", "other"),
        ("inferred_at", "2026-10-12T10:00:00"),
        ("inference_latency_ms", math.inf),
    ],
)
def test_score_and_identity_semantics(prediction, field, value):
    data = prediction.model_dump()
    data[field] = value
    with pytest.raises(ValidationError):
        DNSThreatPrediction.model_validate(data)


def test_immutable_receipt_and_provenance(prediction):
    evidence = prediction_to_evidence(prediction, observation_ref="opaque-ref-1")
    assert evidence.evidence_id != prediction_to_evidence(prediction).evidence_id
    assert evidence.prediction.score_type == "uncalibrated_malicious_probability"
    assert evidence.observation_ref == "opaque-ref-1"
    with pytest.raises(ValidationError):
        evidence.source = "network_security_ai"
    with pytest.raises(ValidationError):
        evidence.prediction.artifacts.model_sha256 = "a" * 64
    assert "features" not in evidence.model_dump()
    assert "domain" not in evidence.model_dump_json()


def test_invalid_evidence_metadata(prediction):
    with pytest.raises(ValidationError):
        prediction_to_evidence(prediction, observation_ref="x" * 257)
    with pytest.raises(ValidationError):
        prediction_to_evidence(prediction.model_copy(update={"probability": 2}))
    altered = prediction.model_dump()
    altered["artifacts"]["scaler_sha256"] = "a" * 64
    with pytest.raises(ValidationError):
        DNSThreatPrediction.model_validate(altered)


@pytest.mark.parametrize("path", ["../escape", "/absolute/file", "dir/../../file"])
def test_untrusted_config_path(tmp_path, path):
    with pytest.raises(ValidationError):
        DNSConfig(artifact_root=tmp_path, scaler_path=path)
