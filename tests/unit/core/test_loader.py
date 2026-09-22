from pathlib import Path

import pytest

from graft.core.loader import (
    RuleLoadError,
    dump_rule_to_yaml,
    load_rule_from_str,
    load_rule_from_yaml,
)
from graft.core.models.rule import RuleEnvelope


@pytest.fixture
def valid_yaml_content() -> str:
    return """metadata:
  id: "c4e9b8f2-89b1-4f81-9b16-928d54128f73"
  name: "powershell_encoded_launch"
  description: "Detects execution of PowerShell commands using base64 encoded arguments."
  priority: "high"
  authors:
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
    assert envelope.metadata.priority == "high"
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
  mitre:
    initial_access:
      - "T1059.001"
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
        payload: {}
"""
    with pytest.raises(RuleLoadError, match="MITRE validation failed"):
        load_rule_from_str(invalid_mitre_yaml)


def test_load_reference_example_rule() -> None:
    example_path = Path("rules/secops/custom/workspace_nrd_possible_phishing.yaml")
    envelope = load_rule_from_yaml(example_path)
    assert envelope.metadata.name == "workspace_nrd_possible_phishing"
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
    assert reloaded.metadata.priority == original.metadata.priority
    assert reloaded.metadata.mitre == original.metadata.mitre
    assert reloaded.deployment.enabled == original.deployment.enabled
    assert reloaded.deployment.alerting == original.deployment.alerting
    assert reloaded.deployment.run_frequency == original.deployment.run_frequency
    assert reloaded.runbook == original.runbook
    assert reloaded.logic.strip() == original.logic.strip()
    assert len(reloaded.tests) == len(original.tests)
    assert reloaded.tests[0].id == original.tests[0].id
