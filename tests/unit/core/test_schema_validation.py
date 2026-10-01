import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from graft.core.validation.schema_validator import SchemaValidator


@pytest.fixture
def validator() -> SchemaValidator:
    return SchemaValidator()


@pytest.fixture
def valid_secops_custom_dict() -> dict[str, object]:
    return {
        "metadata": {
            "id": "c4e9b8f2-89b1-4f81-9b16-928d54128f73",
            "name": "powershell_encoded_launch",
            "description": (
                "Detects execution of PowerShell commands using base64 encoded arguments."
            ),
            "owners": ["Security Engineering"],
            "mitre": {
                "execution": ["T1059.001"],
            },
            "tags": ["windows", "powershell"],
            "references": [
                "https://attack.mitre.org/techniques/T1059/001/",
                "Adapted from internal red team exercise (2026)",
            ],
        },
        "logic": (
            'events:\n  $e.target.process.command_line = "powershell -enc"\ncondition:\n  $e\n'
        ),
        "deployment": {
            "enabled": True,
            "alerting": True,
            "run_frequency": "live",
        },
        "runbook": {
            "context": (
                "PowerShell commands with encoded arguments are commonly used "
                "to evade static string matches."
            ),
            "triage": (
                "1. Decode the base64 argument.\n"
                "2. Examine parent process.\n"
                "3. Validate user authority."
            ),
            "response": (
                "1. Quarantine endpoint if unauthorized.\n2. Revoke associated session credentials."
            ),
        },
        "tests": [
            {
                "id": "match_encoded_invocation",
                "description": "Fires alert when encoded command line is observed",
                "expect": 1,
                "events": [
                    {
                        "timestamp": "2026-09-17T12:00:00Z",
                        "payload": {
                            "metadata": {"event_type": "PROCESS_LAUNCH"},
                            "target": {"process": {"command_line": "powershell -enc"}},
                        },
                    }
                ],
            }
        ],
    }


def test_valid_secops_custom_rule_passes(
    validator: SchemaValidator, valid_secops_custom_dict: dict[str, object]
) -> None:
    errors = validator.validate(valid_secops_custom_dict, schema_name="secops_custom")
    assert errors == []
    assert validator.is_valid(valid_secops_custom_dict, schema_name="secops_custom") is True


def test_missing_required_top_level_block(
    validator: SchemaValidator, valid_secops_custom_dict: dict[str, object]
) -> None:
    del valid_secops_custom_dict["logic"]
    errors = validator.validate(valid_secops_custom_dict, schema_name="secops_custom")
    assert len(errors) >= 1
    assert any("logic" in err.message for err in errors)
    assert validator.is_valid(valid_secops_custom_dict, schema_name="secops_custom") is False


def test_unknown_top_level_block_rejected(
    validator: SchemaValidator, valid_secops_custom_dict: dict[str, object]
) -> None:
    valid_secops_custom_dict["unauthorized_custom_field"] = "value"
    errors = validator.validate(valid_secops_custom_dict, schema_name="secops_custom")
    assert len(errors) >= 1
    assert any("unauthorized_custom_field" in err.message for err in errors)


def test_description_length_limit(
    validator: SchemaValidator, valid_secops_custom_dict: dict[str, object]
) -> None:
    metadata = valid_secops_custom_dict["metadata"]
    assert isinstance(metadata, dict)
    metadata["description"] = "A" * 129
    errors = validator.validate(valid_secops_custom_dict, schema_name="secops_custom")
    assert len(errors) >= 1
    assert any("128" in err.message or "maxLength" in err.validator for err in errors)


@pytest.mark.parametrize("disallowed_field", ["status", "priority", "authors"])
def test_disallowed_metadata_fields_rejected(
    validator: SchemaValidator,
    valid_secops_custom_dict: dict[str, object],
    disallowed_field: str,
) -> None:
    metadata = valid_secops_custom_dict["metadata"]
    assert isinstance(metadata, dict)
    metadata[disallowed_field] = "value"
    errors = validator.validate(valid_secops_custom_dict, schema_name="secops_custom")
    assert len(errors) >= 1
    assert any(
        disallowed_field in err.message or "additionalProperties" in err.validator for err in errors
    )


@pytest.mark.parametrize(
    "required_meta_key",
    ["id", "name", "description", "owners", "mitre", "tags", "references"],
)
def test_all_metadata_fields_are_required(
    validator: SchemaValidator,
    valid_secops_custom_dict: dict[str, object],
    required_meta_key: str,
) -> None:
    metadata = valid_secops_custom_dict["metadata"]
    assert isinstance(metadata, dict)
    del metadata[required_meta_key]
    errors = validator.validate(valid_secops_custom_dict, schema_name="secops_custom")
    assert len(errors) >= 1
    assert any(required_meta_key in err.message for err in errors)


@pytest.mark.parametrize(
    ("field_name", "bad_value"),
    [
        ("owners", []),
        ("owners", ["Team A", "Team A"]),
        ("owners", ["   "]),
        ("mitre", {}),
        ("mitre", {"execution": []}),
        ("mitre", {"execution": ["T1059.001", "T1059.001"]}),
        ("tags", []),
        ("tags", ["gcp", "gcp"]),
        ("references", []),
        ("references", ["Same Ref", "Same Ref"]),
        ("references", ["   "]),
        ("description", "   "),
    ],
)
def test_metadata_collection_and_blank_constraints(
    validator: SchemaValidator,
    valid_secops_custom_dict: dict[str, object],
    field_name: str,
    bad_value: object,
) -> None:
    metadata = valid_secops_custom_dict["metadata"]
    assert isinstance(metadata, dict)
    metadata[field_name] = bad_value
    assert validator.is_valid(valid_secops_custom_dict, schema_name="secops_custom") is False


def test_whitespace_only_logic_and_runbook_rejected(
    validator: SchemaValidator, valid_secops_custom_dict: dict[str, object]
) -> None:
    valid_secops_custom_dict["logic"] = "   \n  "
    assert validator.is_valid(valid_secops_custom_dict, schema_name="secops_custom") is False

    valid_secops_custom_dict["logic"] = "events:\n  $e\ncondition:\n  $e"
    runbook = valid_secops_custom_dict["runbook"]
    assert isinstance(runbook, dict)
    for rb_key in ("context", "triage", "response"):
        original = runbook[rb_key]
        runbook[rb_key] = "   "
        assert validator.is_valid(valid_secops_custom_dict, schema_name="secops_custom") is False
        runbook[rb_key] = original


def test_test_event_timestamp_and_payload_constraints(
    validator: SchemaValidator, valid_secops_custom_dict: dict[str, object]
) -> None:
    tests = valid_secops_custom_dict["tests"]
    assert isinstance(tests, list)
    event = tests[0]["events"][0]

    event["timestamp"] = ""
    assert validator.is_valid(valid_secops_custom_dict, schema_name="secops_custom") is False

    event["timestamp"] = "not-a-timestamp"
    assert validator.is_valid(valid_secops_custom_dict, schema_name="secops_custom") is False

    event["timestamp"] = "2026-09-17T12:00:00Z"
    event["payload"] = {}
    assert validator.is_valid(valid_secops_custom_dict, schema_name="secops_custom") is False


@pytest.mark.parametrize(
    "bad_name",
    [
        "PowerShell-Rule!",
        "_leading_underscore",
        "trailing_underscore_",
        "double__underscore",
        "a" * 65,
        "_",
    ],
)
def test_invalid_rule_name_pattern(
    validator: SchemaValidator,
    valid_secops_custom_dict: dict[str, object],
    valid_managed_rule_dict: dict[str, object],
    bad_name: str,
) -> None:
    metadata = valid_secops_custom_dict["metadata"]
    assert isinstance(metadata, dict)
    metadata["name"] = bad_name
    errors = validator.validate(valid_secops_custom_dict, schema_name="secops_custom")
    assert len(errors) >= 1

    managed_meta = valid_managed_rule_dict["metadata"]
    assert isinstance(managed_meta, dict)
    managed_meta["name"] = bad_name
    managed_errors = validator.validate(valid_managed_rule_dict, schema_name="base_managed")
    assert len(managed_errors) >= 1


def test_max_64_char_rule_name_passes(
    validator: SchemaValidator,
    valid_secops_custom_dict: dict[str, object],
    valid_managed_rule_dict: dict[str, object],
) -> None:
    name_64 = "a" * 64
    metadata = valid_secops_custom_dict["metadata"]
    assert isinstance(metadata, dict)
    metadata["name"] = name_64
    assert validator.is_valid(valid_secops_custom_dict, schema_name="secops_custom") is True

    managed_meta = valid_managed_rule_dict["metadata"]
    assert isinstance(managed_meta, dict)
    managed_meta["name"] = name_64
    assert validator.is_valid(valid_managed_rule_dict, schema_name="base_managed") is True


def test_mitre_tactic_property_names_use_dashes_and_reject_underscores(
    validator: SchemaValidator, valid_secops_custom_dict: dict[str, object]
) -> None:
    metadata = valid_secops_custom_dict["metadata"]
    assert isinstance(metadata, dict)

    metadata["mitre"] = {"initial-access": ["T1566.002"], "privilege-escalation": ["T1098.001"]}
    assert validator.is_valid(valid_secops_custom_dict, schema_name="secops_custom") is True

    metadata["mitre"] = {"initial_access": ["T1566.002"]}
    errors = validator.validate(valid_secops_custom_dict, schema_name="secops_custom")
    assert len(errors) >= 1
    assert validator.is_valid(valid_secops_custom_dict, schema_name="secops_custom") is False


def test_deployment_run_frequency_mandatory_and_valid_values(
    validator: SchemaValidator, valid_secops_custom_dict: dict[str, object]
) -> None:
    deployment = valid_secops_custom_dict["deployment"]
    assert isinstance(deployment, dict)

    # Missing run_frequency must fail
    del deployment["run_frequency"]
    errors = validator.validate(valid_secops_custom_dict, schema_name="secops_custom")
    assert len(errors) >= 1

    # Valid values: 'unspecified', 'live', 'hourly', 'daily'
    for valid_freq in ["unspecified", "live", "hourly", "daily"]:
        deployment["run_frequency"] = valid_freq
        assert validator.is_valid(valid_secops_custom_dict, schema_name="secops_custom") is True

    # Invalid value
    deployment["run_frequency"] = "weekly"
    assert validator.is_valid(valid_secops_custom_dict, schema_name="secops_custom") is False


def test_deployment_additional_properties_rejected(
    validator: SchemaValidator, valid_secops_custom_dict: dict[str, object]
) -> None:
    deployment = valid_secops_custom_dict["deployment"]
    assert isinstance(deployment, dict)
    deployment["unexpected_key"] = True
    errors = validator.validate(valid_secops_custom_dict, schema_name="secops_custom")
    assert len(errors) >= 1
    assert any("unexpected_key" in err.message for err in errors)


def test_test_expect_non_negative_integer(
    validator: SchemaValidator, valid_secops_custom_dict: dict[str, object]
) -> None:
    tests = valid_secops_custom_dict["tests"]
    assert isinstance(tests, list)

    # expect: -1 must fail
    tests[0]["expect"] = -1
    assert validator.is_valid(valid_secops_custom_dict, schema_name="secops_custom") is False

    # expect: 0 is valid for exclusion/negative test
    tests[0]["expect"] = 0
    assert validator.is_valid(valid_secops_custom_dict, schema_name="secops_custom") is True


def test_test_events_min_items(
    validator: SchemaValidator, valid_secops_custom_dict: dict[str, object]
) -> None:
    tests = valid_secops_custom_dict["tests"]
    assert isinstance(tests, list)
    tests[0]["events"] = []  # minItems is 1
    errors = validator.validate(valid_secops_custom_dict, schema_name="secops_custom")
    assert len(errors) >= 1


def test_valid_managed_manifest_passes(validator: SchemaValidator) -> None:
    manifest = {
        "rulesets": [
            {
                "id": "rs-cloud-threats",
                "name": "Cloud Threat Detections",
                "category": "CLOUD",
                "deployments": [
                    {"type": "PRECISE", "enabled": True, "alerting": True},
                    {"type": "BROAD", "enabled": False, "alerting": False},
                ],
            }
        ],
        "exclusions": [
            {
                "id": "ex-backup-account",
                "rule_id": "r-1",
                "ruleset_id": None,
                "expression": '$e.principal.user.userid != "svc_backup"',
                "description": "Exclude backup service account",
            }
        ],
    }
    assert validator.is_valid(manifest, schema_name="secops_managed") is True


@pytest.mark.parametrize(
    "missing_excl_key",
    ["id", "rule_id", "ruleset_id", "expression", "description"],
)
def test_managed_manifest_all_exclusion_fields_required(
    validator: SchemaValidator, missing_excl_key: str
) -> None:
    exclusion: dict[str, object] = {
        "id": "ex-backup-account",
        "rule_id": "r-1",
        "ruleset_id": None,
        "expression": '$e.principal.user.userid != "svc_backup"',
        "description": "Exclude backup service account",
    }
    del exclusion[missing_excl_key]
    manifest = {
        "rulesets": [],
        "exclusions": [exclusion],
    }
    assert validator.is_valid(manifest, schema_name="secops_managed") is False


def test_managed_manifest_missing_top_level_exclusions_rejected(
    validator: SchemaValidator,
) -> None:
    manifest: dict[str, object] = {"rulesets": []}
    assert validator.is_valid(manifest, schema_name="secops_managed") is False


def test_managed_manifest_blank_exclusion_description_rejected(
    validator: SchemaValidator,
) -> None:
    manifest = {
        "rulesets": [],
        "exclusions": [
            {
                "id": "ex-backup-account",
                "rule_id": "r-1",
                "ruleset_id": None,
                "expression": '$e.principal.user.userid != "svc_backup"',
                "description": "   ",
            }
        ],
    }
    assert validator.is_valid(manifest, schema_name="secops_managed") is False


def test_managed_manifest_unknown_property_rejected(validator: SchemaValidator) -> None:
    manifest: dict[str, object] = {
        "rulesets": [],
        "exclusions": [],
        "invalid_block": {},
    }
    assert validator.is_valid(manifest, schema_name="secops_managed") is False


def test_reference_example_rule_validates_cleanly(validator: SchemaValidator) -> None:
    custom_rules = list(Path("rulesets/secops/custom").glob("*.yaml"))
    assert len(custom_rules) >= 3
    for rule_path in custom_rules:
        data = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        errors = validator.validate(data, schema_name="secops_custom")
        assert errors == []


def test_reference_managed_manifest_validates_cleanly(validator: SchemaValidator) -> None:
    managed_path = Path("rulesets/secops/managed/index.yaml")
    assert managed_path.is_file()
    data = yaml.safe_load(managed_path.read_text(encoding="utf-8"))
    errors = validator.validate(data, schema_name="secops_managed")
    assert errors == []


def test_reference_registered_managed_rules_validate_cleanly(validator: SchemaValidator) -> None:
    managed_rules = [
        p
        for p in Path("rulesets/secops/managed").glob("*.yaml")
        if p.name not in ("index.yaml", "index.yml")
    ]
    assert len(managed_rules) >= 1
    for rule_path in managed_rules:
        data = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        errors = validator.validate(data, schema_name="base_managed")
        assert errors == []


def test_all_schemas_conform_to_draft202012_metaschema() -> None:
    schemas_dir = Path("src/graft/core/schemas")
    schema_files = list(schemas_dir.glob("*.schema.json"))
    for engine_schemas_dir in Path("src/graft/engines").glob("*/schemas"):
        schema_files.extend(engine_schemas_dir.glob("*.schema.json"))
    assert len(schema_files) >= 3

    for sf in schema_files:
        schema = json.loads(sf.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)


def test_schema_validator_discovers_engine_schemas(tmp_path: Path) -> None:
    schemas_dir = tmp_path / "schemas"
    schemas_dir.mkdir(parents=True)
    base_custom = Path("src/graft/core/schemas/base_custom.schema.json").read_text(encoding="utf-8")
    (schemas_dir / "base_custom.schema.json").write_text(base_custom, encoding="utf-8")

    engines_dir = tmp_path / "engines"
    test_engine_schemas = engines_dir / "mock_siem" / "schemas"
    test_engine_schemas.mkdir(parents=True)
    (test_engine_schemas / "custom.schema.json").write_text(
        """{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "mock_siem_custom.schema.json",
  "allOf": [
    { "$ref": "base_custom.schema.json" },
    {
      "type": "object",
      "properties": {
        "deployment": {
          "type": "object",
          "required": ["mock_tier"],
          "properties": {
            "mock_tier": { "type": "string" }
          }
        }
      }
    }
  ]
}""",
        encoding="utf-8",
    )

    validator = SchemaValidator(schemas_dir=schemas_dir, engines_dir=engines_dir)
    assert "mock_siem:custom" in validator.available_schemas()
    assert "mock_siem_custom" in validator.available_schemas()

    valid_inst = {
        "metadata": {
            "id": "11111111-1111-4111-8111-111111111111",
            "name": "test_rule",
            "description": "desc",
            "owners": ["Detection Team"],
            "mitre": {"execution": ["T1059.001"]},
            "tags": ["mock"],
            "references": ["Internal doc"],
        },
        "logic": "test logic",
        "deployment": {"mock_tier": "gold"},
        "runbook": {"context": "c", "triage": "t", "response": "r"},
        "tests": [],
    }
    assert validator.is_valid(valid_inst, schema_name="mock_siem:custom") is True

    invalid_inst = {
        "metadata": {
            "id": "11111111-1111-4111-8111-111111111111",
            "name": "test_rule",
            "description": "desc",
            "owners": ["Detection Team"],
            "mitre": {"execution": ["T1059.001"]},
            "tags": ["mock"],
            "references": ["Internal doc"],
        },
        "logic": "test logic",
        "deployment": {"mock_tier": 123},
        "runbook": {"context": "c", "triage": "t", "response": "r"},
        "tests": [],
    }
    assert validator.is_valid(invalid_inst, schema_name="mock_siem:custom") is False


@pytest.fixture
def valid_managed_rule_dict() -> dict[str, object]:
    return {
        "metadata": {
            "id": "c4e9b8f2-89b1-4f81-9b16-928d54128f73",
            "name": "gcti_active_breach_host_indicators",
            "description": "Registers GCTI Active Breach Priority Host Indicators ruleset.",
            "owners": ["Security Operations"],
            "mitre": {
                "command-and-control": ["T1071.001"],
            },
            "tags": ["secops", "managed", "gcti"],
            "references": [
                "https://docs.cloud.google.com/chronicle/docs/detection/curated-detections"
            ],
        },
        "managed": {
            "id": "f5533b66-9327-9880-93e6-75a738ac2345",
        },
        "runbook": {
            "context": "High-confidence host indicators associated with active breaches.",
            "triage": "1. Inspect endpoint telemetry and matched indicator.",
            "response": "1. Isolate host and initiate incident response.",
        },
        "tests": [],
    }


def test_valid_managed_rule_envelope_passes(
    validator: SchemaValidator, valid_managed_rule_dict: dict[str, object]
) -> None:
    errors = validator.validate(valid_managed_rule_dict, schema_name="base_managed")
    assert errors == []
    assert validator.is_valid(valid_managed_rule_dict, schema_name="base_managed") is True


def test_managed_rule_rejects_logic_and_deployment_blocks(
    validator: SchemaValidator, valid_managed_rule_dict: dict[str, object]
) -> None:
    with_logic = {**valid_managed_rule_dict, "logic": "events: $e condition: $e"}
    assert validator.is_valid(with_logic, schema_name="base_managed") is False

    with_deployment = {**valid_managed_rule_dict, "deployment": {"enabled": True}}
    assert validator.is_valid(with_deployment, schema_name="base_managed") is False


def test_managed_rule_requires_non_empty_managed_id(
    validator: SchemaValidator, valid_managed_rule_dict: dict[str, object]
) -> None:
    valid_managed_rule_dict["managed"] = {}
    assert validator.is_valid(valid_managed_rule_dict, schema_name="base_managed") is False

    valid_managed_rule_dict["managed"] = {"id": "   "}
    assert validator.is_valid(valid_managed_rule_dict, schema_name="base_managed") is False

    valid_managed_rule_dict["managed"] = {"id": "non-uuid-vendor-id_123", "extra": "nope"}
    assert validator.is_valid(valid_managed_rule_dict, schema_name="base_managed") is False

    valid_managed_rule_dict["managed"] = {"id": "non-uuid-vendor-id_123"}
    assert validator.is_valid(valid_managed_rule_dict, schema_name="base_managed") is True


def test_rule_name_index_is_reserved_and_rejected(
    validator: SchemaValidator,
    valid_secops_custom_dict: dict[str, object],
    valid_managed_rule_dict: dict[str, object],
) -> None:
    custom_meta = valid_secops_custom_dict["metadata"]
    assert isinstance(custom_meta, dict)
    custom_meta["name"] = "index"
    assert validator.is_valid(valid_secops_custom_dict, schema_name="secops_custom") is False

    managed_meta = valid_managed_rule_dict["metadata"]
    assert isinstance(managed_meta, dict)
    managed_meta["name"] = "index"
    assert validator.is_valid(valid_managed_rule_dict, schema_name="base_managed") is False
