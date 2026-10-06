"""Benchmark input semantics without dataset IO, inference, or result writes."""

import importlib.util
from pathlib import Path
from unittest.mock import Mock

import numpy as np
import pandas as pd
import pytest


@pytest.fixture
def benchmark():
    path = Path(__file__).parents[1] / "benchmark_model_memory.py"
    spec = importlib.util.spec_from_file_location("network_memory_benchmark", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("scale_for_dnn", [False, True])
def test_model_specific_preprocessing_uses_shared_package(benchmark, monkeypatch, scale_for_dnn):
    names = [f"feature_{i}" for i in range(40)]
    raw = np.ones((2, 40), dtype=np.float32)
    raw[0, 0] = np.inf
    table = Mock()
    table.to_pandas.return_value = pd.DataFrame(raw, columns=names)
    parquet = Mock()
    parquet.iter_batches.return_value = iter([table])
    monkeypatch.setattr(benchmark.pd, "read_csv", lambda path: pd.DataFrame({"feature": names}))
    monkeypatch.setattr(benchmark.pq, "ParquetFile", lambda path: parquet)
    scaler = Mock()
    scaler.mean_ = np.arange(40, dtype=np.float32)
    scaler.transform.side_effect = lambda values: values / 2
    loader = Mock(return_value=scaler)
    monkeypatch.setattr(benchmark.joblib, "load", loader)
    result = benchmark.load_input(2, scale_for_dnn=scale_for_dnn)
    if scale_for_dnn:
        loader.assert_called_once_with(benchmark.SCALER_PATH)
        scaler.transform.assert_called_once()
        assert result[0, 0] == 0
        assert result[1, 0] == 0.5
    else:
        loader.assert_not_called()
        assert np.isnan(result[0, 0])
        assert result[1, 0] == 1
    parquet.iter_batches.assert_called_once_with(batch_size=2, columns=names)
