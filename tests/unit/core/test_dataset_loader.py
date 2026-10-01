from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from graft.core.loader import (
    DatasetLoadError,
    dataset_to_dict,
    dump_dataset_to_yaml,
    load_dataset_from_str,
    load_dataset_from_yaml,
)
from graft.core.models.dataset import DatasetEnvelope, DatasetMetadata


@pytest.fixture
def valid_dataset_yaml() -> str:
    return """metadata:
  name: "known_scanner_ips"
  description: "Authorized internal vulnerability scanners and discovery nodes."
  owners:
    - "Security Operations"
  tags:
    - "network"
    - "scanner"
  references:
    - "https://lopes.id/log/detection-rules-netscan-portscan/"

values:
  - "10.10.0.50"  # Primary vulnerability scanner appliance
  - "10.10.0.51"  # Secondary scanner appliance
"""


def test_dataset_models_immutability() -> None:
    meta = DatasetMetadata(
        name="vip_users",
        description="Executive user accounts.",
        owners=("SOC",),
        tags=("identity",),
        references=("https://internal.wiki/vip",),
    )
    envelope = DatasetEnvelope(metadata=meta, values=("ceo@corp.example.com",))
    assert envelope.metadata.name == "vip_users"
    assert envelope.values == ("ceo@corp.example.com",)

    with pytest.raises(FrozenInstanceError):
        envelope.values = ()  # type: ignore[misc]


def test_load_dataset_from_str_success_with_inline_comments(valid_dataset_yaml: str) -> None:
    dataset = load_dataset_from_str(valid_dataset_yaml)
    assert isinstance(dataset, DatasetEnvelope)
    assert dataset.metadata.name == "known_scanner_ips"
    assert dataset.metadata.description.startswith("Authorized internal")
    assert dataset.metadata.owners == ("Security Operations",)
    assert dataset.metadata.tags == ("network", "scanner")
    assert dataset.values == ("10.10.0.50", "10.10.0.51")


def test_load_dataset_from_yaml_and_roundtrip(valid_dataset_yaml: str, tmp_path: Path) -> None:
    ds_file = tmp_path / "known_scanner_ips.yaml"
    ds_file.write_text(valid_dataset_yaml, encoding="utf-8")

    loaded = load_dataset_from_yaml(ds_file)
    assert loaded.metadata.name == "known_scanner_ips"

    dumped_path = tmp_path / "out" / "known_scanner_ips.yaml"
    dump_dataset_to_yaml(loaded, dumped_path)
    assert dumped_path.is_file()

    reloaded = load_dataset_from_yaml(dumped_path)
    assert reloaded == loaded
    doc = dataset_to_dict(reloaded)
    assert set(doc.keys()) == {"metadata", "values"}


def test_load_dataset_rejects_filename_mismatch_with_metadata_name(
    valid_dataset_yaml: str,
    tmp_path: Path,
) -> None:
    mismatched_file = tmp_path / "wrong_filename.yaml"
    mismatched_file.write_text(valid_dataset_yaml, encoding="utf-8")
    with pytest.raises(DatasetLoadError, match="must match filename stem"):
        load_dataset_from_yaml(mismatched_file)


@pytest.mark.parametrize(
    "bad_name",
    [
        "1starts_with_digit",
        "_leading_underscore",
        "trailing_underscore_",
        "double__underscore",
        "bad-hyphen",
        "Uppercase_Dataset",
        "index",
        "a" * 65,
    ],
)
def test_load_dataset_rejects_invalid_identifiers(tmp_path: Path, bad_name: str) -> None:
    yaml_text = f"""metadata:
  name: "{bad_name}"
  description: "Invalid dataset name test"
  owners: ["SOC"]
  tags: ["network"]
  references: ["ref"]
values:
  - "10.0.0.1"
"""
    with pytest.raises(DatasetLoadError):
        load_dataset_from_str(yaml_text)

    bad_file = tmp_path / f"{bad_name}.yaml"
    bad_file.write_text(yaml_text, encoding="utf-8")
    with pytest.raises(DatasetLoadError):
        load_dataset_from_yaml(bad_file)


def test_load_dataset_value_256_char_limit_and_512_char_raw_line_limit() -> None:
    val_256 = "a" * 256
    comment_200 = "c" * 200
    valid_with_long_comment = f"""metadata:
  name: "long_comment_dataset"
  description: "Dataset with 256-char value and 200-char inline comment."
  owners: ["SOC"]
  tags: ["test"]
  references: ["ref"]
values:
  - "{val_256}" # {comment_200}
"""
    ds = load_dataset_from_str(valid_with_long_comment)
    assert ds.values == (val_256,)

    val_257 = "a" * 257
    invalid_value_len = f"""metadata:
  name: "too_long_value"
  description: "Dataset with 257-char value."
  owners: ["SOC"]
  tags: ["test"]
  references: ["ref"]
values:
  - "{val_257}"
"""
    with pytest.raises(DatasetLoadError, match="Schema validation failed"):
        load_dataset_from_str(invalid_value_len)

    comment_500 = "c" * 500
    invalid_raw_line_len = f"""metadata:
  name: "too_long_raw_line"
  description: "Dataset with raw line exceeding 512 chars."
  owners: ["SOC"]
  tags: ["test"]
  references: ["ref"]
values:
  - "10.0.0.1" # {comment_500}
"""
    with pytest.raises(DatasetLoadError, match="exceeds maximum length of 512"):
        load_dataset_from_str(invalid_raw_line_len)


def test_load_dataset_rejects_empty_duplicate_or_over_1000_values() -> None:
    empty_values = """metadata:
  name: "empty_dataset"
  description: "Empty values list."
  owners: ["SOC"]
  tags: ["test"]
  references: ["ref"]
values: []
"""
    with pytest.raises(DatasetLoadError, match="Schema validation failed"):
        load_dataset_from_str(empty_values)

    duplicate_values = """metadata:
  name: "dup_dataset"
  description: "Duplicate values list."
  owners: ["SOC"]
  tags: ["test"]
  references: ["ref"]
values:
  - "10.0.0.1"
  - "10.0.0.1"
"""
    with pytest.raises(DatasetLoadError, match="Schema validation failed"):
        load_dataset_from_str(duplicate_values)

    items_1001 = "\n".join(f'  - "val_{i}"' for i in range(1001))
    over_1000_values = f"""metadata:
  name: "oversized_dataset"
  description: "More than 1000 values."
  owners: ["SOC"]
  tags: ["test"]
  references: ["ref"]
values:
{items_1001}
"""
    with pytest.raises(DatasetLoadError, match="Schema validation failed"):
        load_dataset_from_str(over_1000_values)


def test_load_dataset_rejects_extra_blocks_like_type() -> None:
    extra_block = """metadata:
  name: "extra_block_dataset"
  description: "Has unsupported type block."
  owners: ["SOC"]
  tags: ["test"]
  references: ["ref"]
type: "cidr"
values:
  - "10.0.0.1"
"""
    with pytest.raises(DatasetLoadError, match="Schema validation failed"):
        load_dataset_from_str(extra_block)
