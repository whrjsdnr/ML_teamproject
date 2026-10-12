"""Select one observation/model per call; sequential use takes separate inputs."""

import argparse
import sys
from pathlib import Path

from dns_security_ai.cli import read_features
from dns_security_ai.errors import DNSSecurityAIError
from network_security_ai.errors import SecurityAIError
from pydantic import ValidationError

from security_ai.common.evidence import to_envelope


def main() -> int:
    if sys.argv[1:2] == ["artifacts"]:
        from security_ai.artifact_cli import main as artifact_main

        return artifact_main(sys.argv[2:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", choices=("network", "dns"))
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--observation-ref")
    parser.add_argument("--profile", choices=("detection_quality", "edge"))
    parser.add_argument("--runtime", choices=("litert", "tensorflow"))
    args = parser.parse_args()
    try:
        features = read_features(args.input)
        if args.source == "network":
            if args.runtime is not None:
                raise ValueError("Runtime applies only to DNS")
            from security_ai.network import (
                NetworkSecurityAIConfig,
                create_network_security_ai,
                prediction_to_evidence,
            )

            predictor = create_network_security_ai(
                NetworkSecurityAIConfig(
                    enabled=True,
                    artifact_root=args.artifact_root,
                    profile=args.profile or "detection_quality",
                )
            )
            assert predictor is not None
            evidence = prediction_to_evidence(
                predictor.predict(features), flow_reference=args.observation_ref
            )
        else:
            if args.profile is not None:
                raise ValueError("Profile applies only to Network")
            from security_ai.dns import DNSConfig, DNSPredictor
            from security_ai.dns import prediction_to_evidence as dns_evidence

            predictor = DNSPredictor(
                DNSConfig(
                    artifact_root=args.artifact_root,
                    runtime=args.runtime or "litert",
                )
            )
            evidence = dns_evidence(
                predictor.predict(features), observation_ref=args.observation_ref
            )
        print(to_envelope(evidence).model_dump_json(indent=2))
    except (
        DNSSecurityAIError,
        SecurityAIError,
        ValidationError,
        ValueError,
        OSError,
        RecursionError,
    ):
        print(
            "Security AI inference failed; validate input and trusted artifacts.", file=sys.stderr
        )
        return 1
    return 0
