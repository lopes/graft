from pathlib import Path
from typing import Any

import pytest
import yaml

from graft.cli.scaffold import scaffold_rule
from graft.core.loader import RuleLoadError, load_rule_from_yaml
from graft.core.validation.schema_validator import SchemaValidator
from graft.engines.secops.compiler import synthesize_yaral_rule


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
        "tests": [],
    }


def test_valid_secops_custom_rule_passes(
    validator: SchemaValidator, valid_secops_custom_dict: dict[str, object]
) -> None:
    errors = validator.validate(valid_secops_custom_dict, schema_name="secops_custom")
    assert errors == []
    assert validator.is_valid(valid_secops_custom_dict, schema_name="secops_custom") is True


def test_deployment_run_frequency_mandatory_and_valid_values(
    validator: SchemaValidator, valid_secops_custom_dict: dict[str, object]
) -> None:
    deployment = valid_secops_custom_dict["deployment"]
    assert isinstance(deployment, dict)

    del deployment["run_frequency"]
    errors = validator.validate(valid_secops_custom_dict, schema_name="secops_custom")
    assert len(errors) >= 1

    for valid_freq in ["unspecified", "live", "hourly", "daily"]:
        deployment["run_frequency"] = valid_freq
        assert validator.is_valid(valid_secops_custom_dict, schema_name="secops_custom") is True

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


def test_load_reference_example_rule() -> None:
    example_path = Path("rulesets/secops/custom/workspace_nrd_email_opened.yaml")
    envelope = load_rule_from_yaml(example_path)
    assert envelope.metadata.name == "workspace_nrd_email_opened"
    assert envelope.deployment.run_frequency == "live"
    assert len(envelope.tests) == 2


def test_load_rule_from_yaml_resolves_secops_schema_from_rulesets_dir(tmp_path: Path) -> None:
    rule_dir = tmp_path / "rulesets" / "secops" / "custom"
    rule_dir.mkdir(parents=True)
    rule_file = rule_dir / "invalid_freq.yaml"
    rule_file.write_text(
        """metadata:
  id: "c4e9b8f2-89b1-4f81-9b16-928d54128f73"
  name: "bad_frequency_rule"
  description: "Detects bad frequency"
  owners:
    - "SecOps"
  mitre:
    execution:
      - "T1059.001"
  tags:
    - "secops"
  references:
    - "Internal"
logic: |
  events:
    $e.metadata.event_type = "USER_LOGIN"
  condition:
    $e
deployment:
  enabled: true
  alerting: true
  run_frequency: "invalid_frequency_value"
runbook:
  context: "c"
  triage: "t"
  response: "r"
tests: []
""",
        encoding="utf-8",
    )

    with pytest.raises(RuleLoadError, match="Schema validation failed"):
        load_rule_from_yaml(rule_file)


def test_scaffold_secops_rule_synthesizes_yaral(tmp_path: Path) -> None:
    rule_path = scaffold_rule("secops", "suspicious_powershell_execution", project_root=tmp_path)
    envelope = load_rule_from_yaml(rule_path, schema_name="secops_custom")
    synth_text, _ = synthesize_yaral_rule(envelope)
    assert synth_text.count("rule suspicious_powershell_execution {") == 1


def test_secops_workflow_steps_and_cloud_gates() -> None:
    pr_path = Path(".github/workflows/pr-validation.yml")
    pr_data: dict[str, Any] = yaml.safe_load(pr_path.read_text(encoding="utf-8"))
    jobs = pr_data.get("jobs", {})

    cloud_job = jobs.get("secops-cloud-gates", {})
    assert "dependabot[bot]" in str(cloud_job.get("if", ""))
    cloud_perms = cloud_job.get("permissions", {})
    assert cloud_perms.get("id-token") == "write"
    assert cloud_perms.get("pull-requests") == "write"
    assert cloud_perms.get("issues") == "write"

    pr_steps = [s.get("run", "") for j in jobs.values() for s in j.get("steps", []) if "run" in s]
    assert any("graft secops verify --env staging" in r for r in pr_steps)
    assert any("graft secops test" in r for r in pr_steps)
    assert any("graft secops diff" in r for r in pr_steps)

    deploy_path = Path(".github/workflows/deploy-production.yml")
    deploy_data: dict[str, Any] = yaml.safe_load(deploy_path.read_text(encoding="utf-8"))
    deploy_jobs = deploy_data.get("jobs", {})
    deploy_steps = [
        s.get("run", "") for j in deploy_jobs.values() for s in j.get("steps", []) if "run" in s
    ]
    assert any("graft secops apply" in r for r in deploy_steps)
