"""Clone/package independence and the reviewed training metadata contract."""

import ast
import hashlib
import json
import os
import subprocess
import sys
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

from network_security_ai import NetworkSecurityAIConfig, Top40Contract
from network_security_ai.contracts import NetworkArtifactError
from network_security_ai.errors import SecurityAIInferenceError
from network_security_ai.predictors import LightGBMNetworkThreatPredictor
from network_security_ai.preprocessing import preprocess_dnn_batch


@pytest.mark.parametrize(
    "name,field",
    [
        ("top40_features.csv", "top40_path"),
        ("label_mapping.json", "label_mapping_path"),
    ],
)
def test_bundled_metadata_matches_training_fixture_and_manifest(name, field):
    content = files("network_security_ai").joinpath("resources", name).read_bytes()
    assert content == (Path(__file__).parent / "fixtures" / name).read_bytes()
    manifest = json.loads(
        files("network_security_ai").joinpath("artifact_manifest.json").read_bytes()
    )
    assert hashlib.sha256(content).hexdigest() == manifest["sha256"][field]


def test_default_contract_requires_no_external_data_or_results(tmp_path):
    config = NetworkSecurityAIConfig(enabled=True, artifact_root=tmp_path)
    contract = Top40Contract(config)
    example = Path(__file__).parents[1] / "examples/synthetic_top40.json"
    assert set(json.loads(example.read_text())) == set(contract.names)
    assert len(contract.classes) == 15
    assert not list(tmp_path.iterdir())
    with pytest.raises(NetworkArtifactError, match="missing"):
        LightGBMNetworkThreatPredictor(config, contract).predict(dict.fromkeys(contract.names, 0))


def test_explicit_metadata_override_fails_closed(tmp_path):
    config = NetworkSecurityAIConfig(artifact_root=tmp_path, top40_path="missing.csv")
    with pytest.raises(NetworkArtifactError, match="missing"):
        Top40Contract(config)
    (tmp_path / "wrong.csv").write_text("rank,feature\n1,invented\n")
    with pytest.raises(NetworkArtifactError, match="checksum"):
        Top40Contract(config.model_copy(update={"top40_path": Path("wrong.csv")}))


def test_preprocessing_batch_preserves_input_and_uses_only_fitted_mean():
    source = np.ones((3, 40), dtype=np.float32)
    source[0, 0], source[1, 1], source[2, 2] = np.nan, np.inf, -np.inf
    original = source.copy()
    captured = []

    def transform(values):
        captured.append(values.copy())
        return values / 2

    scaler = SimpleNamespace(mean_=np.arange(40), transform=transform)
    output = preprocess_dnn_batch(source, scaler)
    np.testing.assert_equal(source, original)
    assert captured[0][0, 0] == 0
    assert captured[0][1, 1] == 1
    assert captured[0][2, 2] == 2
    assert output.shape == (3, 40)
    assert output.dtype == np.float32
    assert np.isfinite(output).all()


@pytest.mark.parametrize("shape", [(40,), (1, 39), (1, 40, 1)])
def test_preprocessing_rejects_non_top40_batch(shape):
    with pytest.raises(SecurityAIInferenceError, match="Top40"):
        preprocess_dnn_batch(np.zeros(shape), SimpleNamespace(mean_=np.zeros(40)))


def test_runtime_source_has_no_soc_imports_or_user_absolute_paths():
    source = Path(__file__).parents[1] / "src/network_security_ai"
    for path in source.rglob("*.py"):
        text = path.read_text()
        assert "/home/geonug/" not in text
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.Import):
                assert all(not alias.name.startswith("soc_agent") for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("soc_agent")


def test_installed_package_import_in_isolated_process_without_soc(tmp_path):
    code = """
import sys
from pathlib import Path
import network_security_ai
from network_security_ai import NetworkSecurityAIConfig, Top40Contract
assert not any('autonomous-soc-agent' in path for path in sys.path)
assert not any(name == 'soc_agent' or name.startswith('soc_agent.') for name in sys.modules)
contract = Top40Contract(NetworkSecurityAIConfig(artifact_root=Path('.')))
assert len(contract.names) == 40 and len(contract.classes) == 15
assert not any(name in sys.modules for name in ('torch', 'lightgbm', 'torchao'))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", code],
        cwd=tmp_path,
        env={"PATH": os.defpath},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
