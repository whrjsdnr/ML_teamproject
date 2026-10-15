"""Admission tests use synthetic declarations only, never a training dataset."""

from dataclasses import replace

import pytest

from ml.verified_producers.contracts import digest
from ml.verified_producers.dataset import Sample, dataset_manifest


def declarations():
    return tuple(
        Sample(
            str(i),
            digest({"raw": i}),
            i % 2,
            f"independent-label-row:{i}",
            "INDEPENDENT_DATASET_LABEL",
            f"source-family:{i}",
            split,
            "RAW_FQDN",
            "RAW_DATASET",
        )
        for i, split in enumerate(
            ["train", "train", "validation", "validation", "test", "test"]
        )
    )


def test_declarations_are_not_training_authority():
    records = declarations()
    result = dataset_manifest("fixture-declarations", "1", "dns", records)
    assert result == dataset_manifest("fixture-declarations", "1", "dns", records[::-1])
    assert result["dataset_size"] == 6
    assert result["validation_status"] == "DECLARATIONS_ONLY_NOT_TRAINING_AUTHORITY"
    assert not result["raw_bytes_verified"]
    assert not result["label_authority_verified"]
    assert not result["temporal_holdout_verified"]
    assert result["operational_promotion"] == "BLOCKED"


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_origin", "SYNTHETIC"),
        ("raw_kind", "PRECOMPUTED_FEATURES"),
        ("label_origin", "OPERATOR_JUDGMENT"),
        ("label_origin", "MODEL_OUTPUT"),
        ("label_reference", ""),
        ("label", True),
        ("raw_digest", "not-a-digest"),
        ("source_group", ""),
        ("split", "unknown"),
    ],
)
def test_untrusted_or_missing_data(field, value):
    rows = list(declarations())
    rows[0] = replace(rows[0], **{field: value})
    with pytest.raises(ValueError):
        dataset_manifest("fixture", "1", "dns", tuple(rows))


@pytest.mark.parametrize("field", ["raw_digest", "sample_id", "source_group"])
def test_duplicates_and_group_leakage(field):
    rows = list(declarations())
    rows[-1] = replace(rows[-1], **{field: getattr(rows[0], field)})
    with pytest.raises(ValueError):
        dataset_manifest("fixture", "1", "dns", tuple(rows))


def test_missing_holdout_or_class():
    with pytest.raises(ValueError):
        dataset_manifest("fixture", "1", "dns", declarations()[:4])
    with pytest.raises(ValueError):
        dataset_manifest("fixture", "1", "dns", ())


def test_feature_only_network_data_is_rejected():
    rows = tuple(replace(s, raw_kind="CICFLOWMETER_CSV") for s in declarations())
    with pytest.raises(ValueError, match="RAW_LABELED_DATA_REQUIRED"):
        dataset_manifest("feature-only", "1", "network", rows)
