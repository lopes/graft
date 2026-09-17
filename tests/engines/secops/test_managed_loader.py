from pathlib import Path

import pytest

from graft.core.models.managed import (
    ManagedDeployment,
    ManagedExclusion,
    ManagedRuleSet,
    ManagedState,
)
from graft.engines.secops.managed_loader import (
    ManagedManifestLoadError,
    dump_managed_manifest_to_yaml,
    load_managed_manifest_from_str,
    load_managed_manifest_from_yaml,
)


def test_load_managed_manifest_from_reference_file() -> None:
    path = Path("rules/secops/managed.yaml")
    state = load_managed_manifest_from_yaml(path)

    assert len(state.rulesets) == 2
    rs1, rs2 = state.rulesets
    assert rs1.id == "rs-cloud-threats"
    assert rs1.name == "Cloud Threat Detections"
    assert rs1.category == "CLOUD"
    assert len(rs1.deployments) == 2
    assert rs1.deployments[0] == ManagedDeployment(type="PRECISE", enabled=True, alerting=True)
    assert rs1.deployments[1] == ManagedDeployment(type="BROAD", enabled=False, alerting=False)

    assert rs2.id == "rs-linux-threats"
    assert rs2.category == "ENDPOINT"

    assert len(state.exclusions) == 1
    ex = state.exclusions[0]
    assert ex.id == "ex-backup-service-account"
    assert ex.rule_id == "ru_cloud_iam_privilege_escalation"
    assert ex.ruleset_id == "rs-cloud-threats"
    assert "svc_automation_backup" in ex.expression
    assert "Exclude scheduled" in ex.description


def test_load_managed_manifest_from_str() -> None:
    yaml_content = """
rulesets:
  - id: "rs-auth"
    name: "Auth Threats"
    category: "IDENTITY"
    deployments:
      - type: "PRECISE"
        enabled: true
        alerting: false
exclusions:
  - id: "ex-scanner"
    rule_id: null
    ruleset_id: "rs-auth"
    expression: '$e.principal.ip != "10.0.0.1"'
    description: "Ignore scanner IP"
"""
    state = load_managed_manifest_from_str(yaml_content)
    assert len(state.rulesets) == 1
    assert state.rulesets[0].id == "rs-auth"
    assert len(state.exclusions) == 1
    assert state.exclusions[0].id == "ex-scanner"
    assert state.exclusions[0].rule_id is None


def test_load_managed_manifest_corrupted_yaml() -> None:
    with pytest.raises(ManagedManifestLoadError, match="YAML parsing error"):
        load_managed_manifest_from_str("rulesets: [unterminated")


def test_load_managed_manifest_schema_failure() -> None:
    # Missing required 'rulesets'
    with pytest.raises(ManagedManifestLoadError, match="Schema validation failed"):
        load_managed_manifest_from_str("exclusions: []")


def test_dump_managed_manifest_and_roundtrip(tmp_path: Path) -> None:
    original_state = ManagedState(
        rulesets=(
            ManagedRuleSet(
                id="rs-test",
                name="Test Ruleset",
                category="TEST",
                deployments=(
                    ManagedDeployment(type="PRECISE", enabled=True, alerting=True),
                    ManagedDeployment(type="BROAD", enabled=False, alerting=False),
                ),
            ),
        ),
        exclusions=(
            ManagedExclusion(
                id="ex-test",
                rule_id="ru_1",
                ruleset_id="rs-test",
                expression='$e.principal.user.userid != "tester"',
                description="Test exclusion",
            ),
        ),
    )

    out_file = tmp_path / "managed.yaml"
    dumped_str = dump_managed_manifest_to_yaml(original_state, path=out_file)

    assert "rs-test" in dumped_str
    assert "ex-test" in dumped_str
    assert out_file.exists()

    loaded_state = load_managed_manifest_from_yaml(out_file)
    assert loaded_state == original_state
