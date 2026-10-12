import pytest

from dns_security_ai.artifacts import manifest
from dns_security_ai.contracts import DNSArtifactReference, DNSFeatureContract, DNSThreatPrediction


@pytest.fixture
def dns_features():
    return dict(zip(DNSFeatureContract.names, [14, 0, 0, 2.78, 2, 2, 10, 6.5, 11], strict=True))


@pytest.fixture
def prediction():
    bundle = manifest()["artifacts"]
    return DNSThreatPrediction(
        class_id=1,
        label="MALICIOUS",
        probability=0.75,
        runtime="litert",
        inference_latency_ms=1,
        artifacts=DNSArtifactReference(
            model_sha256=bundle["model_path"]["sha256"],
            scaler_sha256=bundle["scaler_path"]["sha256"],
        ),
    )
