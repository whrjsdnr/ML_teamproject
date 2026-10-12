"""Bounded standalone DNS JSON inference; emits immutable evidence data."""

import argparse
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from dns_security_ai.contracts import DNSConfig
from dns_security_ai.errors import DNSSecurityAIError
from dns_security_ai.evidence import prediction_to_evidence
from dns_security_ai.predictor import DNSPredictor


def read_features(path: Path, *, max_bytes: int = 65536) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("Input JSON is oversized")

    def pairs(items: list[tuple[str, object]]) -> dict:
        result = dict(items)
        if len(result) != len(items):
            raise ValueError("Duplicate JSON keys")
        return result

    value = json.loads(raw, object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise ValueError("Expected a feature mapping")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--runtime", choices=("litert", "tensorflow"), default="litert")
    parser.add_argument("--observation-ref")
    args = parser.parse_args()
    try:
        prediction = DNSPredictor(
            DNSConfig(artifact_root=args.artifact_root, runtime=args.runtime)
        ).predict(read_features(args.input))
        print(
            prediction_to_evidence(
                prediction, observation_ref=args.observation_ref
            ).model_dump_json(indent=2)
        )
    except (DNSSecurityAIError, ValidationError, ValueError, OSError, RecursionError):
        print("DNS inference failed; validate input and trusted artifacts.", file=sys.stderr)
        return 1
    return 0
