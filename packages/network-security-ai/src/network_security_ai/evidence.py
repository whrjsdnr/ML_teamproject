"""Pure Network evidence output. SOC ingestion and evidence fusion are deferred."""

from typing import Literal

from network_security_ai.contracts import NetworkThreatPrediction
from network_security_ai.schema import NonEmptyText, Snapshot


class NetworkSecurityEvidence(Snapshot):
    source: Literal["network_security_ai"] = "network_security_ai"
    evidence_type: Literal["network_threat_prediction"] = "network_threat_prediction"
    prediction: NetworkThreatPrediction
    flow_reference: NonEmptyText | None = None
    model_derived: Literal[True] = True
    confidence_calibrated: Literal[False] = False
    # An inference receipt is not confirmation of an attack or permission to act.
    attack_confirmed: Literal[False] = False
    schema_version: Literal["network-evidence-v1"] = "network-evidence-v1"


def prediction_to_evidence(
    prediction: NetworkThreatPrediction, *, flow_reference: str | None = None
) -> NetworkSecurityEvidence:
    """Convert data only; no imports, tools, actions, SOC state, or raw features."""
    return NetworkSecurityEvidence(prediction=prediction, flow_reference=flow_reference)
