"""Unacquired candidates cannot become ADMITTED through manifest assertions."""

from dataclasses import asdict, dataclass
from pathlib import Path

from ml.raw_acquisition.binding import feature_contract_digest
from ml.verified_producers.contracts import contract, digest


@dataclass(frozen=True)
class AcquisitionCandidate:
    dataset_id: str
    official_source: str
    version: str | None
    license: str | None
    raw_file_identity: tuple[str, ...]
    label_file_identity: tuple[str, ...]
    downloadable_file_list_verified: bool
    raw_source_fields_reported: bool
    limitations: tuple[str, ...]

    @property
    def state(self) -> str:
        if (
            self.downloadable_file_list_verified
            and self.license
            and self.raw_file_identity
            and self.raw_source_fields_reported
        ):
            return "ACQUISITION_READY"
        return "INSUFFICIENT_EVIDENCE"


def pending_manifest(candidate: AcquisitionCandidate, kind: str) -> dict[str, object]:
    config = contract(kind)
    declaration = {
        k: ("UNKNOWN" if v is None else v) for k, v in asdict(candidate).items()
    }
    body = {
        **declaration,
        "acquisition_state": candidate.state,
        "raw_sha256": "UNKNOWN",
        "label_sha256": "UNKNOWN",
        "producer_version": "1.0.0",
        "producer_config_digest": digest(config),
        "feature_contract_digest": feature_contract_digest(kind),
        "split_identity": "UNKNOWN",
        "sample_count": "UNKNOWN",
        "class_distribution": "UNKNOWN",
        "exclusion_count": "UNKNOWN",
        "dataset_digest": "UNKNOWN",
        "readiness": "BLOCKED",
        "admission": "NOT_ADMITTED",
        "actual_training_authority": "NONE",
        "operational_input": "NOT_INFERABLE",
        "write_disposition": "WRITE_DENIED",
    }
    return body | {"manifest_digest": digest(body)}


def verify_manifest(document: dict[str, object]) -> None:
    body = {k: v for k, v in document.items() if k != "manifest_digest"}
    if document.get("manifest_digest") != digest(body):
        raise ValueError("MANIFEST_DIGEST_MISMATCH")
    if body.get("producer_version") != "1.0.0":
        raise ValueError("PRODUCER_VERSION_MISMATCH")
    if body.get("admission") != "NOT_ADMITTED" or body.get("readiness") != "BLOCKED":
        raise ValueError("PENDING_MANIFEST_CANNOT_ADMIT_DATA")
    if (
        body.get("operational_input") != "NOT_INFERABLE"
        or body.get("write_disposition") != "WRITE_DENIED"
        or body.get("actual_training_authority") != "NONE"
    ):
        raise ValueError("MANIFEST_PROMOTION_DENIED")
    # This pending-only schema cannot assert acquired bytes by adding a digest.
    if any(
        body.get(k) != "UNKNOWN"
        for k in (
            "raw_sha256",
            "label_sha256",
            "dataset_digest",
            "split_identity",
            "sample_count",
            "class_distribution",
            "exclusion_count",
        )
    ):
        raise ValueError("ACQUIRED_DATA_REQUIRES_SEPARATE_VERIFIED_ADMISSION")
    for kind in ("network", "dns"):
        if body.get("producer_config_digest") == digest(contract(kind)) and body.get(
            "feature_contract_digest"
        ) == feature_contract_digest(kind):
            return
    raise ValueError("PRODUCER_CONTRACT_MISMATCH")


def verify_local_file(path: Path, expected_sha256: str, max_bytes: int) -> int:
    """Reverify local receipts before binding; this alone does not admit a dataset."""
    import hashlib
    import os
    import re
    import stat

    if (
        type(max_bytes) is not int
        or max_bytes < 1
        or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
    ):
        raise ValueError("INVALID_SOURCE_RECEIPT")
    if path.is_symlink():
        raise ValueError("SYMLINK_SOURCE_DENIED")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    sha = hashlib.sha256()
    total = 0
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("REGULAR_SOURCE_REQUIRED")
        while block := stream.read(65536):
            total += len(block)
            if total > max_bytes:
                raise ValueError("SOURCE_SIZE_LIMIT")
            sha.update(block)
    if sha.hexdigest() != expected_sha256:
        raise ValueError("SOURCE_TAMPERING")
    return total
