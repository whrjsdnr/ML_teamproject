"""Trusted LOCAL research joblib only, digest checked before deserialization.

SHA256 is integrity, not authenticity. Never accept a manifest/hash from an untrusted
party. There is no runtime registration or general model-file loading interface.
"""

import hashlib
import io
import json
import os
import stat
from pathlib import Path

import joblib
import sklearn

from ml.network_research.dataset import verify_seal
from ml.verified_producers.contracts import digest
from ml.verified_producers.network_v1_1 import feature_contract, producer_contract


def local_bytes(path: Path, root: Path, limit: int) -> bytes:
    if root.is_symlink() or root.resolve() != root.absolute() or path.parent != root:
        raise ValueError("UNTRUSTED_ARTIFACT_PATH")
    meta = root.stat()
    if meta.st_uid != os.getuid() or stat.S_IMODE(meta.st_mode) & 0o077:
        raise ValueError("UNSAFE_ARTIFACT_ROOT")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        if (
            not stat.S_ISREG(meta.st_mode)
            or meta.st_uid != os.getuid()
            or stat.S_IMODE(meta.st_mode) & 0o022
            or meta.st_size > limit
        ):
            raise ValueError("UNSAFE_ARTIFACT_FILE")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("ARTIFACT_SIZE_LIMIT")
        return data
    finally:
        os.close(fd)


def load_research(
    root: Path, *, trusted_manifest_digest: str, purpose: str = "research"
):
    if purpose != "research":
        raise ValueError("NO_OPERATIONAL_PROMOTION")
    document = json.loads(local_bytes(root / "artifact.json", root, 1024**2))
    verify_seal(document)
    if (
        document["manifest_digest"] != trusted_manifest_digest
        or document.get("status") != "RESEARCH_ONLY"
        or document.get("operational_promotion") is not False
    ):
        raise ValueError("UNTRUSTED_RESEARCH_MANIFEST")
    if (
        document["sklearn_version"] != sklearn.__version__
        or document["producer_config_digest"] != digest(producer_contract())
        or document["feature_contract_digest"] != digest(feature_contract())
    ):
        raise ValueError("ARTIFACT_RUNTIME_OR_FEATURE_MISMATCH")
    data = local_bytes(root / "model.joblib", root, 32 * 1024**2)
    if hashlib.sha256(data).hexdigest() != document["model_sha256"]:
        raise ValueError("ARTIFACT_DIGEST_MISMATCH")
    model = joblib.load(io.BytesIO(data))
    if not hasattr(model, "predict_proba") or list(model.classes_) != [0, 1]:
        raise ValueError("INVALID_RESEARCH_MODEL")
    return model, document
