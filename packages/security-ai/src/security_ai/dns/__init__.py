"""Re-export the canonical independent DNS package; no second predictor implementation."""

from dns_security_ai import (
    DNSConfig,
    DNSFeatureContract,
    DNSPredictor,
    DNSSecurityEvidence,
    DNSThreatPrediction,
    prediction_to_evidence,
)

__all__ = [
    "DNSConfig",
    "DNSFeatureContract",
    "DNSPredictor",
    "DNSSecurityEvidence",
    "DNSThreatPrediction",
    "prediction_to_evidence",
]
