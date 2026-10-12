"""Re-export the existing canonical Network API without modifying it."""

from network_security_ai import (
    DeploymentProfile,
    NetworkSecurityAIConfig,
    NetworkSecurityEvidence,
    NetworkThreatPrediction,
    Top40Contract,
    create_network_security_ai,
    prediction_to_evidence,
)

__all__ = [
    "DeploymentProfile",
    "NetworkSecurityAIConfig",
    "NetworkSecurityEvidence",
    "NetworkThreatPrediction",
    "Top40Contract",
    "create_network_security_ai",
    "prediction_to_evidence",
]
