"""Compare supplied detector preprocessing/output with new API using the SAME LiteRT.

This verifies migration parity, not native TensorFlow equivalence or training
preprocessing provenance. No original source/artifact is modified.
"""

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np
from ai_edge_litert.interpreter import Interpreter
from dns_security_ai import DNSConfig, DNSPredictor
from dns_security_ai.contracts import FEATURE_NAMES
from dns_security_ai.predictor import load_runtime
from dns_security_ai.preprocessing import quantize_input


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    config = DNSConfig(artifact_root=args.legacy_root)
    p = DNSPredictor(config)
    p._runtime = load_runtime(config)  # Check trusted checksums before original loader.
    spec = importlib.util.spec_from_file_location(
        "review_legacy_dns", args.legacy_root / "detector.py"
    )
    module = importlib.util.module_from_spec(spec)
    # Adapt just the old import to our selected interpreter for algorithm comparison.
    with patch.dict(
        sys.modules,
        {"tensorflow": SimpleNamespace(lite=SimpleNamespace(Interpreter=Interpreter))},
    ):
        spec.loader.exec_module(module)
        original = module.DNSDetector(
            model_path=args.legacy_root / config.model_path,
            scaler_path=args.legacy_root / config.scaler_path,
        )
    rows = [
        np.zeros(9),
        np.array([14, 0, 0, 2.7813014714884527, 2, 2, 10, 6.5, 11]),
        np.array([27, 10, 11, 2.767194748898957, 6, 6, 7, 3.6666666666666665, 14]),
    ]
    rows.extend(np.random.default_rng(42).uniform(0, 300, (32, 9)))
    for row in rows:
        features = dict(zip(FEATURE_NAMES, row, strict=True))
        ordered = p.contract.matrix(features)
        r = p._runtime
        np.testing.assert_array_equal(
            quantize_input(ordered, r.scaler, r.input_scale, r.input_zero),
            original._quantize_input(row),
        )
        new, old = p.predict(features), original.predict(row)
        assert new.probability == old["probability"]
        assert new.label == old["label"]
        assert new.threshold == old["threshold"]
    result = {
        "status": "PASS",
        "synthetic_rows": len(rows),
        "quantized_inputs": "byte-identical",
        "probability_and_label": "exact equality",
        "runtime": "same LiteRT 2.3.0 interpreter for both implementations",
        "native_tensorflow_equivalence": "UNVERIFIED: TensorFlow not installed",
        "training_preprocessing_equivalence": "UNVERIFIED: DNN training code absent",
    }
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
