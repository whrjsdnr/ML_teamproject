"""Small synthetic smoke/resource probe. No datasets, fitting or accuracy evaluation.

Run one backend per process for meaningful independent peak RSS. Batch 32 is a
sequence of 32 public single-row calls, not native vectorized batch inference.
"""

import argparse
import importlib.metadata
import json
import platform
import resource
import statistics
import time
from pathlib import Path

from security_ai import to_envelope


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backend", choices=("network-quality", "network-edge", "dns"))
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    started = time.perf_counter()
    if args.backend == "dns":
        from dns_security_ai import DNSConfig, DNSPredictor, prediction_to_evidence
        from dns_security_ai.predictor import load_runtime

        predictor = DNSPredictor(DNSConfig(artifact_root=args.artifact_root))
        features = dict(
            zip(
                predictor.contract.names,
                [14, 0, 0, 2.7813014714884527, 2, 2, 10, 6.5, 11],
                strict=True,
            )
        )
        load_start = time.perf_counter()
        predictor._runtime = load_runtime(predictor.config)
    else:
        from network_security_ai import (
            NetworkSecurityAIConfig,
            create_network_security_ai,
            prediction_to_evidence,
        )
        from network_security_ai.predictors import load_dnn, load_lightgbm

        profile = "edge" if args.backend == "network-edge" else "detection_quality"
        adapter = create_network_security_ai(
            NetworkSecurityAIConfig(
                enabled=True,
                artifact_root=args.artifact_root,
                profile=profile,
            )
        )
        assert adapter is not None
        predictor = adapter.predictor
        features = dict(zip(predictor.contract.names, range(40), strict=True))
        load_start = time.perf_counter()
        if profile == "edge":
            predictor._runtime = load_dnn(predictor.config, predictor.contract)
        else:
            predictor._model = load_lightgbm(predictor.config, predictor.contract)
    load_ms = (time.perf_counter() - load_start) * 1000
    prediction = predictor.predict(features)
    first_ms = (time.perf_counter() - started) * 1000
    envelope = to_envelope(prediction_to_evidence(prediction))
    for _ in range(5):
        predictor.predict(features)
    batches = {}
    for size in (1, 32):
        times = []
        for _ in range(10):
            start = time.perf_counter_ns()
            for _ in range(size):
                predictor.predict(features)
            times.append((time.perf_counter_ns() - start) / 1_000_000)
        batches[str(size)] = {
            "calls_per_trial": size,
            "trials": 10,
            "median_ms": statistics.median(times),
            "max_ms": max(times),
        }
    versions = {}
    for name in (
        "numpy",
        "pandas",
        "pydantic",
        "scikit-learn",
        "joblib",
        "lightgbm",
        "torch",
        "ai-edge-litert",
    ):
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    result = {
        "backend": args.backend,
        "input": "synthetic; no accuracy claim",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "versions": versions,
        "model_load_ms": load_ms,
        "setup_and_first_prediction_ms": first_ms,
        "latency": batches,
        "peak_rss_mib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
        "measurement": "independent Linux process; warm API calls incl validation; sequential batch",
        "output": envelope.model_dump(mode="json"),
    }
    # Do not replace a previous experimental measurement by accident.
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({k: v for k, v in result.items() if k != "output"}, indent=2))


if __name__ == "__main__":
    main()
