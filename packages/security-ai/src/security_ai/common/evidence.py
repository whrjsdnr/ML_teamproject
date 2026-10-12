"""A receipt envelope, not fusion, SOC evidence ingestion or execution authority."""

from typing import Literal, Self
from uuid import UUID, uuid4

from dns_security_ai.contracts import Snapshot, Text, Timestamp
from dns_security_ai.evidence import DNSSecurityEvidence
from network_security_ai.evidence import NetworkSecurityEvidence
from pydantic import Field, field_validator, model_validator


class EvidenceEnvelope(Snapshot):
    schema_version: Literal["security-ai-envelope-v1"] = "security-ai-envelope-v1"
    evidence_id: UUID = Field(default_factory=uuid4)
    evidence_type: Literal["network_threat_prediction", "dns_threat_prediction"]
    source: Literal["network_security_ai", "dns_security_ai"]
    model_id: Text
    model_version: Text
    # Inference timestamp, never asserted to be the observation timestamp.
    timestamp: Timestamp
    observation_ref: Text | None = None
    payload: NetworkSecurityEvidence | DNSSecurityEvidence

    @field_validator("payload", mode="before")
    @classmethod
    def revalidate_payload(cls, value: object) -> object:
        # Existing Network Snapshot.model_copy can bypass validation.
        if isinstance(value, (NetworkSecurityEvidence, DNSSecurityEvidence)):
            return type(value).model_validate(value.model_dump())
        return value

    @model_validator(mode="after")
    def provenance(self) -> Self:
        payload = self.payload
        p = payload.prediction
        if isinstance(payload, NetworkSecurityEvidence):
            model_id, ref = p.model_name, payload.flow_reference
        else:
            model_id, ref = p.model_id, payload.observation_ref
            if self.evidence_id != payload.evidence_id:
                raise ValueError("DNS envelope must retain the payload evidence ID")
        if (
            self.evidence_type != payload.evidence_type
            or self.source != payload.source
            or self.model_id != model_id
            or self.model_version != p.model_version
            or self.timestamp != p.inferred_at
            or self.observation_ref != ref
        ):
            raise ValueError("Envelope provenance differs from its typed payload")
        return self


def to_envelope(evidence: NetworkSecurityEvidence | DNSSecurityEvidence) -> EvidenceEnvelope:
    if type(evidence) not in (NetworkSecurityEvidence, DNSSecurityEvidence):
        raise TypeError("Expected a supported typed security evidence")
    evidence = type(evidence).model_validate(evidence.model_dump())
    p = evidence.prediction
    if isinstance(evidence, NetworkSecurityEvidence):
        identity = dict(model_id=p.model_name, observation_ref=evidence.flow_reference)
    else:
        identity = dict(
            evidence_id=evidence.evidence_id,
            model_id=p.model_id,
            observation_ref=evidence.observation_ref,
        )
    return EvidenceEnvelope(
        source=evidence.source,
        evidence_type=evidence.evidence_type,
        model_version=p.model_version,
        timestamp=p.inferred_at,
        payload=evidence,
        **identity,
    )
