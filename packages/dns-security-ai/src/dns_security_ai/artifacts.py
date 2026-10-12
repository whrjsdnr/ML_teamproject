"""Verify reviewed bytes before native model parsing or trusted joblib loading."""

import hashlib
import json
from functools import lru_cache
from importlib.resources import files

from dns_security_ai.contracts import (
    FEATURE_DIGEST,
    FEATURE_NAMES,
    FEATURE_VERSION,
    MODEL_ID,
    MODEL_VERSION,
    DNSConfig,
)
from dns_security_ai.errors import DNSArtifactError


@lru_cache(maxsize=1)
def _manifest_bytes() -> bytes:
    return files("dns_security_ai").joinpath("artifact_manifest.json").read_bytes()


def manifest() -> dict:
    """Return a detached metadata copy; callers cannot mutate the cached manifest."""
    try:
        value = json.loads(_manifest_bytes())
        if (
            value["bundle_version"] != "dns-int8-reviewed-1"
            or value["model_id"] != MODEL_ID
            or value["model_version"] != MODEL_VERSION
            or value["feature_schema_version"] != FEATURE_VERSION
            or value["feature_names"] != list(FEATURE_NAMES)
            or value["feature_contract_digest"] != FEATURE_DIGEST
            or value["class_mapping"] != {"NORMAL": 0, "MALICIOUS": 1}
            or value["threshold"] != 0.5
            or set(value["artifacts"]) != {"model_path", "scaler_path"}
        ):
            raise ValueError("Incompatible bundle metadata")
        for entry in value["artifacts"].values():
            digest = entry["sha256"]
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)
                or type(entry["size_bytes"]) is not int
                or entry["size_bytes"] <= 0
            ):
                raise ValueError("Invalid artifact metadata")
        return value
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise DNSArtifactError("Invalid packaged DNS manifest") from error


def verify_bundle(config: DNSConfig) -> dict[str, object]:
    config = DNSConfig.model_validate(config.model_dump())
    result = {}
    for field, entry in manifest()["artifacts"].items():
        try:
            path = config.artifact(getattr(config, field))
            if path.stat().st_size != entry["size_bytes"]:
                raise DNSArtifactError("Artifact size differs from reviewed bundle")
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            if digest.hexdigest() != entry["sha256"]:
                raise DNSArtifactError("Artifact checksum differs from reviewed bundle")
            result[field] = path
        except OSError as error:
            raise DNSArtifactError("Cannot read trusted artifact") from error
    return result
