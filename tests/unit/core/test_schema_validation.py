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
            "priority": "high",
            "authors": ["Security Engineering"],
            "mitre": {
                "execution": ["T1059.001"],
            },
            "tags": ["windows", "powershell"],
            "references": ["https://attack.mitre.org/techniques/T1059/001/"],
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


def test_status_field_disallowed(
    validator: SchemaValidator, valid_secops_custom_dict: dict[str, object]
) -> None:
    metadata = valid_secops_custom_dict["metadata"]
    assert isinstance(metadata, dict)
    metadata["status"] = "production"
    errors = validator.validate(valid_secops_custom_dict, schema_name="secops_custom")
    assert len(errors) >= 1
    assert any("status" in err.message or "additionalProperties" in err.validator for err in errors)


def test_invalid_rule_name_pattern(
    validator: SchemaValidator, valid_secops_custom_dict: dict[str, object]
) -> None:
    metadata = valid_secops_custom_dict["metadata"]
    assert isinstance(metadata, dict)
    metadata["name"] = "PowerShell-Rule!"  # Must be lowercase slug ^[a-z0-9_]+$
    errors = validator.validate(valid_secops_custom_dict, schema_name="secops_custom")
    assert len(errors) >= 1


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


def test_managed_manifest_unknown_property_rejected(validator: SchemaValidator) -> None:
    manifest: dict[str, object] = {
        "rulesets": [],
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
    managed_path = Path("rulesets/secops/managed.yaml")
    assert managed_path.is_file()
    data = yaml.safe_load(managed_path.read_text(encoding="utf-8"))
    errors = validator.validate(data, schema_name="secops_managed")
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
    base_rule = Path("src/graft/core/schemas/base_rule.schema.json").read_text(encoding="utf-8")
    (schemas_dir / "base_rule.schema.json").write_text(base_rule, encoding="utf-8")

    engines_dir = tmp_path / "engines"
    test_engine_schemas = engines_dir / "mock_siem" / "schemas"
    test_engine_schemas.mkdir(parents=True)
    (test_engine_schemas / "rule.schema.json").write_text(
        """{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "rule.schema.json",
  "allOf": [
    { "$ref": "base_rule.schema.json" },
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
    assert "mock_siem:rule" in validator.available_schemas()
    assert "mock_siem_rule" in validator.available_schemas()

    valid_inst = {
        "metadata": {
            "id": "11111111-1111-4111-8111-111111111111",
            "name": "test_rule",
            "description": "desc",
        },
        "logic": "test logic",
        "deployment": {"mock_tier": "gold"},
        "runbook": {"context": "c", "triage": "t", "response": "r"},
        "tests": [],
    }
    assert validator.is_valid(valid_inst, schema_name="mock_siem:rule") is True

    invalid_inst = {
        "metadata": {
            "id": "11111111-1111-4111-8111-111111111111",
            "name": "test_rule",
            "description": "desc",
        },
        "logic": "test logic",
        "deployment": {"mock_tier": 123},
        "runbook": {"context": "c", "triage": "t", "response": "r"},
        "tests": [],
    }
    assert validator.is_valid(invalid_inst, schema_name="mock_siem:rule") is False
