from pathlib import Path

import pytest

from graft.core.loader import (
    RuleLoadError,
    dump_rule_to_yaml,
    load_rule_from_str,
    load_rule_from_yaml,
    rule_to_dict,
)
from graft.core.models.rule import (
    BaseDeploymentConfig,
    RuleEnvelope,
    RuleMetadata,
    Runbook,
)


@pytest.fixture
def valid_yaml_content() -> str:
    return """metadata:
  id: "c4e9b8f2-89b1-4f81-9b16-928d54128f73"
  name: "powershell_encoded_launch"
  description: "Detects execution of PowerShell commands using base64 encoded arguments."
  owners:
    - "Security Engineering"
  mitre:
    execution:
      - "T1059.001"
  tags:
    - "windows"
    - "powershell"
  references:
    - "https://attack.mitre.org/techniques/T1059/001/"

logic: |
  events:
    $e.target.process.command_line = "powershell -enc"
  condition:
    $e

deployment:
  enabled: true
  alerting: true
  run_frequency: "live"

runbook:
  context: |
    PowerShell commands with encoded arguments are commonly used to evade static string matches.
  triage: |
    1. Decode the base64 argument.
    2. Examine parent process.
    3. Validate user authority.
  response: |
    1. Quarantine endpoint if unauthorized.
    2. Revoke associated session credentials.

tests:
  - id: "match_encoded_invocation"
    description: "Fires alert when encoded command line is observed"
    expect: 1
    events:
      - timestamp: "2026-09-17T12:00:00Z"
        payload:
          metadata:
            event_type: "PROCESS_LAUNCH"
          target:
            process:
              command_line: "powershell -enc"
"""


def test_load_rule_from_str_success(valid_yaml_content: str) -> None:
    envelope = load_rule_from_str(valid_yaml_content)
    assert isinstance(envelope, RuleEnvelope)
    assert envelope.metadata.id == "c4e9b8f2-89b1-4f81-9b16-928d54128f73"
    assert envelope.metadata.name == "powershell_encoded_launch"
    assert envelope.metadata.owners == ("Security Engineering",)
    assert envelope.metadata.mitre == {"execution": ("T1059.001",)}
    assert envelope.deployment.enabled is True
    assert envelope.deployment.alerting is True
    assert envelope.deployment.run_frequency == "live"
    assert envelope.runbook.context.startswith("PowerShell commands")
    assert len(envelope.tests) == 1
    assert envelope.tests[0].id == "match_encoded_invocation"
    assert envelope.tests[0].expect == 1
    assert len(envelope.tests[0].events) == 1
    assert envelope.tests[0].events[0].payload["metadata"]["event_type"] == "PROCESS_LAUNCH"  # type: ignore[index]


def test_load_rule_from_yaml_file(valid_yaml_content: str, tmp_path: Path) -> None:
    rule_file = tmp_path / "test_rule.yaml"
    rule_file.write_text(valid_yaml_content, encoding="utf-8")

    envelope = load_rule_from_yaml(rule_file)
    assert envelope.metadata.name == "powershell_encoded_launch"


def test_load_rule_corrupted_yaml() -> None:
    bad_yaml = "metadata: [unbalanced brackets"
    with pytest.raises(RuleLoadError, match="YAML parsing error"):
        load_rule_from_str(bad_yaml)


def test_load_rule_schema_validation_failure() -> None:
    invalid_schema_yaml = """metadata:
  id: "invalid-uuid"
  name: "Bad Name!"
  description: "Desc"
logic: ""
deployment:
  enabled: true
runbook:
  context: "c"
  triage: "t"
  response: "r"
tests: []
"""
    with pytest.raises(RuleLoadError, match="Schema validation failed"):
        load_rule_from_str(invalid_schema_yaml)


def test_load_rule_mitre_validation_failure() -> None:
    invalid_mitre_yaml = """metadata:
  id: "c4e9b8f2-89b1-4f81-9b16-928d54128f73"
  name: "rule_test"
  description: "Test rule description"
  owners:
    - "Security Engineering"
  mitre:
    initial-access:
      - "T1059.001"
  tags:
    - "test"
  references:
    - "Internal reference"
logic: |
  events:
    $e.metadata.event_type = "USER_LOGIN"
  condition:
    $e
deployment:
  enabled: true
  alerting: true
  run_frequency: "unspecified"
runbook:
  context: "c"
  triage: "t"
  response: "r"
tests:
  - id: "t1"
    description: "test"
    expect: 0
    events:
      - timestamp: "2026-09-17T12:00:00Z"
        payload:
          metadata:
            event_type: "USER_LOGIN"
"""
    with pytest.raises(RuleLoadError, match="MITRE validation failed"):
        load_rule_from_str(invalid_mitre_yaml)


def test_load_reference_example_rule() -> None:
    example_path = Path("rulesets/secops/custom/workspace_nrd_email_opened.yaml")
    envelope = load_rule_from_yaml(example_path)
    assert envelope.metadata.name == "workspace_nrd_email_opened"
    assert envelope.deployment.run_frequency == "live"
    assert len(envelope.tests) == 2


def test_dump_rule_and_roundtrip(valid_yaml_content: str, tmp_path: Path) -> None:
    original = load_rule_from_str(valid_yaml_content)
    dump_target = tmp_path / "dumped_rule.yaml"

    dump_rule_to_yaml(original, dump_target)
    assert dump_target.is_file()

    reloaded = load_rule_from_yaml(dump_target)
    assert reloaded.metadata.id == original.metadata.id
    assert reloaded.metadata.name == original.metadata.name
    assert reloaded.metadata.description == original.metadata.description
    assert reloaded.metadata.owners == original.metadata.owners
    assert reloaded.metadata.mitre == original.metadata.mitre
    assert reloaded.metadata.tags == original.metadata.tags
    assert reloaded.metadata.references == original.metadata.references
    assert reloaded.deployment.enabled == original.deployment.enabled
    assert reloaded.deployment.alerting == original.deployment.alerting
    assert reloaded.deployment.run_frequency == original.deployment.run_frequency
    assert reloaded.runbook == original.runbook
    assert reloaded.logic.strip() == original.logic.strip()
    assert len(reloaded.tests) == len(original.tests)
    assert reloaded.tests[0].id == original.tests[0].id


def test_rule_to_dict_always_emits_all_metadata_keys_even_when_empty(tmp_path: Path) -> None:
    unpopulated_rule = RuleEnvelope(
        metadata=RuleMetadata(
            id="c4e9b8f2-89b1-4f81-9b16-928d54128f73",
            name="pulled_unpopulated_rule",
            description="Imported rule awaiting operator enrichment",
            owners=(),
            mitre={},
            tags=(),
            references=(),
        ),
        logic='events:\n  $e.metadata.event_type = "USER_LOGIN"\ncondition:\n  $e',
        deployment=BaseDeploymentConfig(enabled=False, alerting=False, run_frequency="live"),
        runbook=Runbook(context="c", triage="t", response="r"),
        tests=(),
    )
    doc = rule_to_dict(unpopulated_rule)
    assert set(doc["metadata"].keys()) == {
        "id",
        "name",
        "description",
        "owners",
        "mitre",
        "tags",
        "references",
    }
    assert doc["metadata"]["owners"] == []
    assert doc["metadata"]["mitre"] == {}
    assert doc["metadata"]["tags"] == []
    assert doc["metadata"]["references"] == []

    # Dumping and attempting to load without enriching must fail schema validation
    dumped_path = tmp_path / "unpopulated.yaml"
    dump_rule_to_yaml(unpopulated_rule, dumped_path)
    with pytest.raises(RuleLoadError, match="Schema validation failed"):
        load_rule_from_yaml(dumped_path)


def test_load_rule_from_yaml_resolves_engine_schema_from_rulesets_dir(tmp_path: Path) -> None:
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


def test_load_and_roundtrip_registered_managed_rule(tmp_path: Path) -> None:
    managed_dir = tmp_path / "rulesets" / "secops" / "managed"
    managed_dir.mkdir(parents=True)
    rule_file = managed_dir / "gcti_active_breach_host_indicators.yaml"
    rule_file.write_text(
        """metadata:
  id: "c4e9b8f2-89b1-4f81-9b16-928d54128f73"
  name: "gcti_active_breach_host_indicators"
  description: "Registers GCTI Active Breach Priority Host Indicators ruleset."
  owners:
    - "Security Operations"
  mitre:
    command-and-control:
      - "T1071.001"
  tags:
    - "secops"
    - "managed"
  references:
    - "https://docs.cloud.google.com/chronicle/docs/detection/curated-detections"
managed:
  id: "f5533b66-9327-9880-93e6-75a738ac2345"
runbook:
  context: "High-confidence host indicators associated with active breaches."
  triage: "1. Inspect endpoint telemetry."
  response: "1. Isolate host."
tests: []
""",
        encoding="utf-8",
    )

    envelope = load_rule_from_yaml(rule_file)
    assert envelope.is_managed is True
    assert envelope.rule_type == "managed"
    assert envelope.managed is not None
    assert envelope.managed.id == "f5533b66-9327-9880-93e6-75a738ac2345"
    assert envelope.logic == ""

    dumped_file = managed_dir / "roundtrip_managed.yaml"
    dump_rule_to_yaml(envelope, dumped_file)
    dumped_dict = rule_to_dict(envelope)
    assert "managed" in dumped_dict
    assert "logic" not in dumped_dict
    assert "deployment" not in dumped_dict

    reloaded = load_rule_from_yaml(dumped_file)
    assert reloaded == envelope


def test_custom_rule_in_managed_dir_fails_schema_validation(tmp_path: Path) -> None:
    managed_dir = tmp_path / "rulesets" / "secops" / "managed"
    managed_dir.mkdir(parents=True)
    bad_file = managed_dir / "custom_in_managed.yaml"
    bad_file.write_text(
        """metadata:
  id: "c4e9b8f2-89b1-4f81-9b16-928d54128f73"
  name: "custom_in_managed"
  description: "Custom rule placed in managed folder"
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
  run_frequency: "live"
runbook:
  context: "c"
  triage: "t"
  response: "r"
tests: []
""",
        encoding="utf-8",
    )

    with pytest.raises(RuleLoadError, match="Schema validation failed"):
        load_rule_from_yaml(bad_file)


@pytest.mark.parametrize(
    "bad_filename",
    [
        "_leading_underscore.yaml",
        "trailing_underscore_.yaml",
        "double__underscore.yaml",
        "hyphen-name.yaml",
        "Uppercase_Rule.yaml",
        f"{'a' * 65}.yaml",
        "index.yaml",
        "index.yml",
    ],
)
def test_load_rule_from_yaml_rejects_invalid_filename_stem(
    valid_yaml_content: str,
    tmp_path: Path,
    bad_filename: str,
) -> None:
    bad_file = tmp_path / bad_filename
    bad_file.write_text(valid_yaml_content, encoding="utf-8")
    with pytest.raises(RuleLoadError, match="Invalid rule filename"):
        load_rule_from_yaml(bad_file)


def test_load_rule_from_yaml_allows_valid_64_char_filename_different_from_metadata_name(
    valid_yaml_content: str,
    tmp_path: Path,
) -> None:
    stem_64 = "a" * 64
    rule_file = tmp_path / f"{stem_64}.yaml"
    rule_file.write_text(valid_yaml_content, encoding="utf-8")
    envelope = load_rule_from_yaml(rule_file)
    assert envelope.metadata.name == "powershell_encoded_launch"
