import numpy as np
import pytest

from dns_security_ai.contracts import FEATURE_NAMES
from dns_security_ai.errors import DNSArtifactError
from dns_security_ai.preprocessing import quantize_input, validate_scaler


@pytest.fixture
def dns_scaler():
    sklearn = pytest.importorskip("sklearn.preprocessing")
    pytest.importorskip("pandas")
    # Construct deterministic fitted statistics without fitting on inference input.
    s = sklearn.StandardScaler()
    s.feature_names_in_ = np.array(FEATURE_NAMES, dtype=object)
    s.n_features_in_ = 9
    s.n_samples_seen_ = 162880
    s.mean_ = np.arange(9, dtype=np.float64)
    s.scale_ = np.arange(1, 10, dtype=np.float64)
    s.var_ = s.scale_**2
    return s


def test_named_scaler_matches_legacy_numeric_steps(dns_scaler):
    import pandas as pd

    matrix = np.array([[14, 0, 0, 2.78, 2, 2, 10, 6.5, 11]], dtype=np.float32)
    before = dns_scaler.mean_.copy()
    legacy = dns_scaler.transform(pd.DataFrame(matrix, columns=list(FEATURE_NAMES)))
    expected = np.clip(np.round(legacy / 0.0387900173664093 - 40), -128, 127).astype(np.int8)
    actual = quantize_input(matrix, dns_scaler, 0.0387900173664093, -40)
    np.testing.assert_array_equal(actual, expected)
    np.testing.assert_array_equal(dns_scaler.mean_, before)
    validate_scaler(dns_scaler)


def test_reject_equal_dimension_wrong_feature_order(dns_scaler):
    dns_scaler.feature_names_in_ = dns_scaler.feature_names_in_[::-1]
    with pytest.raises(DNSArtifactError):
        validate_scaler(dns_scaler)


@pytest.mark.parametrize(
    "attribute,value",
    [
        ("scale_", np.zeros(9)),
        ("mean_", np.full(9, np.nan)),
        ("n_samples_seen_", 1),
        ("with_std", False),
    ],
)
def test_reject_wrong_scaler(dns_scaler, attribute, value):
    setattr(dns_scaler, attribute, value)
    with pytest.raises(DNSArtifactError):
        validate_scaler(dns_scaler)
