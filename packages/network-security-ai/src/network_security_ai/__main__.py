"""Standalone JSON inference; never sends evidence to SOC or executes actions."""

import argparse
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from network_security_ai import (
    NetworkSecurityAIConfig,
    create_network_security_ai,
    prediction_to_evidence,
)
from network_security_ai.errors import SecurityAIError


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument(
        "--input", type=Path, required=True, help="JSON object of exactly Top40 values"
    )
    parser.add_argument(
        "--profile", choices=("detection_quality", "edge"), default="detection_quality"
    )
    parser.add_argument("--flow-reference")
    args = parser.parse_args()
    try:
        features = json.loads(args.input.read_text(encoding="utf-8"))
        if not isinstance(features, dict):
            raise ValueError("Input must be a JSON object")
        adapter = create_network_security_ai(
            NetworkSecurityAIConfig(
                enabled=True,
                artifact_root=args.artifact_root,
                profile=args.profile,
            )
        )
        assert adapter is not None
        prediction = adapter.predict(features)
        evidence = prediction_to_evidence(prediction, flow_reference=args.flow_reference)
        print(
            json.dumps(
                {
                    "prediction": prediction.model_dump(mode="json"),
                    "evidence": evidence.model_dump(mode="json"),
                },
                ensure_ascii=False,
                allow_nan=False,
                indent=2,
            )
        )
    except (SecurityAIError, ValidationError, ValueError, OSError):
        # Do not echo raw input/path or sensitive backend exception contents.
        print(
            "Network inference failed; validate input, configuration and trusted artifacts.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
