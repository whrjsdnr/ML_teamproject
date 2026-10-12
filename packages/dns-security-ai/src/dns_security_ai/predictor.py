"""Lazy cached TFLite backend. All artifact/runtime operations follow input validation."""

import time
from collections.abc import Mapping
from dataclasses import dataclass
from threading import Lock

import numpy as np

from dns_security_ai.artifacts import manifest, verify_bundle
from dns_security_ai.contracts import (
    DNSArtifactReference,
    DNSConfig,
    DNSFeatureContract,
    DNSThreatPrediction,
)
from dns_security_ai.errors import (
    DNSArtifactError,
    DNSInferenceError,
    DNSOutputError,
    DNSSecurityAIError,
)
from dns_security_ai.preprocessing import dequantize_output, quantize_input, validate_scaler


@dataclass(frozen=True)
class LoadedDNS:
    scaler: object
    interpreter: object
    input_index: int
    output_index: int
    input_scale: float
    input_zero: int
    output_scale: float
    output_zero: int


def load_runtime(config: DNSConfig) -> LoadedDNS:
    paths = verify_bundle(config)  # Both checks happen before any deserialization.
    try:
        import joblib

        if config.runtime == "litert":
            from ai_edge_litert.interpreter import Interpreter
        else:
            import tensorflow as tf

            Interpreter = tf.lite.Interpreter

        scaler = joblib.load(paths["scaler_path"])  # Trusted team pickle only.
        validate_scaler(scaler)
        interpreter = Interpreter(model_path=str(paths["model_path"]), num_threads=1)
        interpreter.allocate_tensors()
        inputs, outputs = interpreter.get_input_details(), interpreter.get_output_details()
        if len(inputs) != 1 or len(outputs) != 1:
            raise DNSArtifactError("Expected one DNS input and one binary output")
        expected = manifest()["tensors"]
        for detail, shape, field in ((inputs[0], (1, 9), "input"), (outputs[0], (1, 1), "output")):
            if (
                tuple(detail["shape"]) != shape
                or detail["dtype"] != np.int8
                or tuple(detail["quantization"]) != tuple(expected[field]["quantization"])
                or len(detail["quantization_parameters"]["scales"]) != 1
                or len(detail["quantization_parameters"]["zero_points"]) != 1
            ):
                raise DNSArtifactError("Tensor contract differs from reviewed INT8 model")
        return LoadedDNS(
            scaler,
            interpreter,
            inputs[0]["index"],
            outputs[0]["index"],
            *inputs[0]["quantization"],
            *outputs[0]["quantization"],
        )
    except DNSArtifactError:
        raise
    except ImportError as error:
        raise DNSInferenceError("Install the selected DNS runtime extra") from error
    except Exception as error:
        raise DNSArtifactError("Failed to load the reviewed DNS bundle") from error


class DNSPredictor:
    def __init__(self, config: DNSConfig) -> None:
        self.config = DNSConfig.model_validate(config.model_dump())
        self.contract = DNSFeatureContract()
        self._runtime: LoadedDNS | None = None
        self._lock = Lock()

    def predict(self, features: Mapping[str, object]) -> DNSThreatPrediction:
        matrix = self.contract.matrix(features)
        started = time.perf_counter_ns()
        try:
            with self._lock:
                if self._runtime is None:
                    self._runtime = load_runtime(self.config)
                r = self._runtime
                values = quantize_input(matrix, r.scaler, r.input_scale, r.input_zero)
                r.interpreter.set_tensor(r.input_index, values)
                r.interpreter.invoke()
                probability = dequantize_output(
                    r.interpreter.get_tensor(r.output_index), r.output_scale, r.output_zero
                )
            bundle = manifest()["artifacts"]
            return DNSThreatPrediction(
                class_id=int(probability >= self.config.threshold),
                label="MALICIOUS" if probability >= self.config.threshold else "NORMAL",
                probability=probability,
                runtime=self.config.runtime,
                artifacts=DNSArtifactReference(
                    model_sha256=bundle["model_path"]["sha256"],
                    scaler_sha256=bundle["scaler_path"]["sha256"],
                ),
                inference_latency_ms=(time.perf_counter_ns() - started) / 1_000_000,
            )
        except DNSSecurityAIError:
            raise
        except ValueError as error:
            raise DNSOutputError("Invalid DNS prediction or preprocessing output") from error
        except Exception as error:
            raise DNSInferenceError("DNS inference failed") from error

    def metadata(self) -> dict:
        return {**manifest(), "runtime": self.config.runtime, "loaded": self._runtime is not None}
