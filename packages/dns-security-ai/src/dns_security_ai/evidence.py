"""No raw DNS payload, event timestamp fabrication, action or policy capability."""

from typing import Literal
from uuid import UUID, uuid4

from pydantic import Field

from dns_security_ai.contracts import DNSThreatPrediction, Snapshot, Text


class DNSSecurityEvidence(Snapshot):
    schema_version: Literal["dns-evidence-v1"] = "dns-evidence-v1"
    evidence_id: UUID = Field(default_factory=uuid4)
    source: Literal["dns_security_ai"] = "dns_security_ai"
    evidence_type: Literal["dns_threat_prediction"] = "dns_threat_prediction"
    prediction: DNSThreatPrediction
    observation_ref: Text | None = None
    model_derived: Literal[True] = True
    confidence_calibrated: Literal[False] = False
    attack_confirmed: Literal[False] = False


def prediction_to_evidence(
    prediction: DNSThreatPrediction, *, observation_ref: str | None = None
) -> DNSSecurityEvidence:
    prediction = DNSThreatPrediction.model_validate(prediction.model_dump())
    return DNSSecurityEvidence(prediction=prediction, observation_ref=observation_ref)
