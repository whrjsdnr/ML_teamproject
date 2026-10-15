"""Security/selection tests use synthetic rows only, never the locked raw session."""

from pathlib import Path
from unittest.mock import Mock

import joblib
import numpy as np
import pytest
import sklearn
from sklearn.linear_model import LogisticRegression

from ml.network_research.artifacts import load_research
from ml.network_research.dataset import (
    leakage,
    load_split,
    seal,
    store_split,
    verify_bound_class,
    verify_seal,
    write_new,
)
from ml.network_research.evaluation import (
    matrix,
    metrics,
    probabilities,
    threshold_from_validation,
)
from ml.network_research.locked_test import final_evaluation, verify_lock
from ml.network_research.training import estimator, select
from ml.verified_producers.contracts import NETWORK_NAMES, digest
from ml.verified_producers.network_v1_1 import feature_contract, producer_contract


def rows(role="train"):
    return [
        {
            "role": role,
            "session": role,
            "flow_id": role + str(i),
            "raw_fingerprint": role + str(i),
            "label_references": [role + str(i)],
            "feature_digest": role + str(i),
            "feature_values_digest": digest([float(i)] * 14),
            "endpoint_hashes": [role],
            "address_hashes": [role],
            "start_ns": i,
            "end_ns": i,
            "values": [float(i)] * 14,
            "y": i,
        }
        for i in range(2)
    ]


def report(data, role="train"):
    return seal(
        {
            "row_digest": digest(data),
            "sample_count": len(data),
            "role": role,
            "producer_version": "1.1.0",
            "feature_names": list(NETWORK_NAMES),
            "producer_config_digest": digest(producer_contract()),
            "feature_contract_digest": digest(feature_contract()),
            "dtype": "float32",
            "origin": "OFFLINE_PCAP",
            "research_only": True,
            "operational_admission": "BLOCKED",
        }
    )


def test_manifest_and_row_tampering(tmp_path):
    data = rows()
    store_split(tmp_path, "train", data, report(data))
    assert load_split(tmp_path, "train")[0] == data
    path = tmp_path / "train.jsonl"
    path.write_text(path.read_text().replace('"y": 0', '"y": 1'))
    with pytest.raises(ValueError, match="MANIFEST"):
        load_split(tmp_path, "train")


def test_manifest_rehash_required():
    doc = seal({"a": 1})
    doc["a"] = 2
    with pytest.raises(ValueError, match="TAMPERED"):
        verify_seal(doc)


@pytest.mark.parametrize(
    "key",
    ["flow_id", "raw_fingerprint", "label_references", "feature_digest", "session"],
)
def test_group_leakage(key):
    left, right = rows(), rows("validation")
    right[0][key] = left[0][key]
    with pytest.raises(ValueError, match="CROSS_SPLIT"):
        leakage(left, right)


def test_feature_values_collision_not_claimed_new_independence():
    assert leakage(rows(), rows("validation"))["feature_values_digest_overlap"] == 2
    assert (
        leakage(rows(), rows("validation"))["host_campaign_independence"]
        == "UNVERIFIED"
    )


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), 0.1])
def test_nonfinite_or_non_float32_rejected(bad):
    data = rows()
    data[0]["values"][0] = bad
    with pytest.raises(ValueError):
        matrix(data)


def test_order_missing_and_invalid_label():
    with pytest.raises(ValueError):
        matrix(rows(), NETWORK_NAMES[::-1])
    for field, value in [("values", [0.0] * 13), ("y", 2)]:
        data = rows()
        data[0][field] = value
        with pytest.raises(ValueError):
            matrix(data)


@pytest.mark.parametrize(
    "p",
    [
        [[0.2, 0.8]],
        [[-1, 2], [0.5, 0.5]],
        [[0.2, 0.2], [0.5, 0.5]],
        [[float("nan"), 1], [0, 1]],
    ],
)
def test_invalid_model_output(p):
    model = Mock(classes_=np.array([0, 1]))
    model.predict_proba.return_value = np.array(p)
    with pytest.raises(ValueError):
        probabilities(model, np.zeros((2, 14)))


def test_class_order_is_not_assumed():
    with pytest.raises(ValueError):
        probabilities(Mock(classes_=[1, 0]), np.zeros((2, 14)))


def test_zero_denominators_unknown():
    result = metrics(np.array([0, 0]), np.array([0.1, 0.2]), 0.5)
    assert result["recall"] is None
    assert result["precision"] is None
    assert result["pr_auc_average_precision"] is None
    assert result["roc_auc"] is None
    assert result["fnr"] is None


def test_threshold_validation_only_deterministic():
    y, p = np.array([0, 0, 1, 1]), np.array([0.1, 0.2, 0.6, 0.8])
    assert threshold_from_validation(y, p) == 0.5
    with pytest.raises(ValueError):
        threshold_from_validation(np.ones(4), p)


def test_train_only_scaler():
    model = estimator("edge_lr")
    x = np.asarray([[0.0] * 14, [2.0] * 14, [4.0] * 14, [6.0] * 14], dtype=np.float32)
    model.fit(x, [0, 0, 1, 1])
    scaler = model.steps[0][1]
    before = scaler.mean_.copy()
    probabilities(model, np.full((2, 14), 999, dtype=np.float32))
    assert scaler.n_samples_seen_ == 4
    np.testing.assert_equal(before, scaler.mean_)


def artifact(tmp_path):
    root = tmp_path / "trusted"
    root.mkdir(mode=0o700)
    model = LogisticRegression().fit([[0.0] * 14, [1.0] * 14], [0, 1])
    joblib.dump(model, root / "model.joblib")
    from ml.iot23.inspect import file_sha256

    doc = seal(
        {
            "status": "RESEARCH_ONLY",
            "operational_promotion": False,
            "sklearn_version": sklearn.__version__,
            "producer_config_digest": digest(producer_contract()),
            "feature_contract_digest": digest(feature_contract()),
            "model_sha256": file_sha256(root / "model.joblib"),
        }
    )
    write_new(root / "artifact.json", doc)
    return root, doc


def test_trusted_local_loading_and_no_promotion(tmp_path):
    root, doc = artifact(tmp_path)
    model, _ = load_research(root, trusted_manifest_digest=doc["manifest_digest"])
    assert list(model.classes_) == [0, 1]
    with pytest.raises(ValueError, match="NO_OPERATIONAL"):
        load_research(
            root, trusted_manifest_digest=doc["manifest_digest"], purpose="runtime"
        )
    with pytest.raises(ValueError):
        load_research(root, trusted_manifest_digest="0" * 64)


def test_model_tampering_rejected_before_deserialize(tmp_path, monkeypatch):
    root, doc = artifact(tmp_path)
    (root / "model.joblib").write_bytes(b"forged")
    loader = Mock(side_effect=AssertionError("must not deserialize"))
    monkeypatch.setattr(joblib, "load", loader)
    with pytest.raises(ValueError, match="DIGEST"):
        load_research(root, trusted_manifest_digest=doc["manifest_digest"])
    loader.assert_not_called()


def test_symlink_model_rejected(tmp_path):
    root, doc = artifact(tmp_path)
    target = tmp_path / "outside"
    (root / "model.joblib").rename(target)
    (root / "model.joblib").symlink_to(target)
    with pytest.raises(OSError):
        load_research(root, trusted_manifest_digest=doc["manifest_digest"])


def test_unsafe_root_rejected(tmp_path):
    root, doc = artifact(tmp_path)
    root.chmod(0o755)
    with pytest.raises(ValueError, match="UNSAFE"):
        load_research(root, trusted_manifest_digest=doc["manifest_digest"])


def test_unknown_candidate_rejected():
    with pytest.raises(ValueError):
        estimator("untrusted.module")


def test_selection_never_has_test_input():
    docs = []
    for name in ["quality_rf", "quality_hgb", "edge_lr", "edge_rf", "edge_hgb"]:
        docs.append(
            {
                "candidate": name,
                "validation_metrics": {
                    "pr_auc_average_precision": 0.99,
                    "f1": 0.95,
                    "recall": 0.95,
                    "fpr": 0.05,
                    "brier": 0.05,
                },
                "benchmark": {
                    "single_row_cpu_p50_ms": 0.01 if name == "edge_lr" else 1.0
                },
                "model_size_bytes": 100,
            }
        )
    assert select(docs)["edge"] == "edge_lr"
    assert select(docs)["quality"] == "quality_rf"


def test_lock_source_tampering(monkeypatch, tmp_path):
    import ml.network_research.locked_test as mod

    monkeypatch.setattr(mod, "code_identity", lambda _: {"file": "a"})
    lock = seal({"evaluation_code_sha256": {"file": "b"}})
    with pytest.raises(ValueError, match="LOCK"):
        verify_lock(lock, tmp_path, trusted_digest=lock["manifest_digest"])


def final_fixture(tmp_path, monkeypatch):
    import ml.network_research.locked_test as mod

    data = tmp_path / "data"
    data.mkdir()
    output = tmp_path / "artifacts"
    output.mkdir()
    selection = seal({"fixed": True})
    write_new(output / "selection.json", selection)
    lock = seal(
        {
            "selection_digest": selection["manifest_digest"],
            "selected": {
                "quality": {
                    "candidate": "q",
                    "manifest_digest": "m",
                    "model_sha256": "s",
                    "threshold": 0.5,
                }
            },
            "train_digest": "train",
            "validation_digest": "validation",
            "diagnostic_digest": "diagnostic",
            "test_raw_sha256": "raw",
            "test_label_sha256": "label",
        }
    )
    write_new(output / "test-lock.json", lock)
    monkeypatch.setattr(mod, "verify_lock", lambda *a, **k: None)
    monkeypatch.setattr(
        mod, "load_split", lambda _, role: (rows(role), {"manifest_digest": role})
    )
    monkeypatch.setattr(
        mod,
        "load_research",
        lambda *a, **k: (object(), {"model_sha256": "s", "threshold": 0.5}),
    )
    monkeypatch.setattr(
        mod,
        "acquisition",
        lambda _: {"test": (Path("unused"), {"sha256": "raw"}, {"sha256": "label"})},
    )
    builder = Mock(return_value=(rows("test"), {"research": True}))
    monkeypatch.setattr(mod, "build_session", builder)
    monkeypatch.setattr(mod, "probabilities", lambda *_: np.array([0.1, 0.9]))
    return mod, data, output, lock, builder


def test_final_pass_once_no_retry(tmp_path, monkeypatch):
    _mod, data, output, lock, builder = final_fixture(tmp_path, monkeypatch)
    result = final_evaluation(
        tmp_path, data, output, trusted_lock_digest=lock["manifest_digest"]
    )
    assert result["evaluation_passes"] == 1
    assert result["operational_promotion"] is False
    with pytest.raises(FileExistsError):
        final_evaluation(
            tmp_path, data, output, trusted_lock_digest=lock["manifest_digest"]
        )
    assert builder.call_count == 1


def test_crash_after_reservation_consumes_attempt(tmp_path, monkeypatch):
    _mod, data, output, lock, builder = final_fixture(tmp_path, monkeypatch)
    builder.side_effect = RuntimeError("fixture crash before result commit")
    with pytest.raises(RuntimeError):
        final_evaluation(
            tmp_path, data, output, trusted_lock_digest=lock["manifest_digest"]
        )
    assert (output / "test-attempt.json").exists()
    assert not (output / "final-test-result.json").exists()
    with pytest.raises(FileExistsError):
        final_evaluation(
            tmp_path, data, output, trusted_lock_digest=lock["manifest_digest"]
        )
    assert builder.call_count == 1


def test_changed_threshold_blocked_before_test_read(tmp_path, monkeypatch):
    mod, data, output, lock, builder = final_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        mod,
        "load_research",
        lambda *a, **k: (object(), {"model_sha256": "s", "threshold": 0.8}),
    )
    with pytest.raises(ValueError, match="THRESHOLD"):
        final_evaluation(
            tmp_path, data, output, trusted_lock_digest=lock["manifest_digest"]
        )
    builder.assert_not_called()
    assert not (output / "test-attempt.json").exists()


@pytest.mark.parametrize(
    "labels, expected",
    [([], "Benign"), (["Benign", "Malicious"], "Benign"), (["Unknown"], "Unknown")],
)
def test_conflicting_or_missing_labels(labels, expected):
    from types import SimpleNamespace

    with pytest.raises(ValueError, match="CONFLICTING"):
        verify_bound_class([SimpleNamespace(label=x) for x in labels], expected)


def test_multiple_concordant_labels_are_one_row():
    from types import SimpleNamespace

    verify_bound_class(
        [SimpleNamespace(label="Malicious"), SimpleNamespace(label="Malicious")],
        "Malicious",
    )


def test_feature_contract_manifest_rejects_reordered_names(tmp_path):
    data = rows()
    wrong = {k: v for k, v in report(data).items() if k != "manifest_digest"}
    wrong["feature_names"] = list(NETWORK_NAMES[::-1])
    store_split(tmp_path, "train", data, seal(wrong))
    with pytest.raises(ValueError, match="CONTRACT"):
        load_split(tmp_path, "train")
