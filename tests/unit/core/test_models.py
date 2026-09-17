from dataclasses import FrozenInstanceError

import pytest

from graft.core.models.compiler import CompilationDiagnostic, CompilationResult
from graft.core.models.managed import (
    ManagedDeployment,
    ManagedExclusion,
    ManagedRuleSet,
    ManagedState,
)
from graft.core.models.rule import (
    BaseDeploymentConfig,
    InvestigationGuide,
    RuleEnvelope,
    RuleMetadata,
    TestEvent,
    TestVector,
)


def test_rule_metadata_immutability() -> None:
    meta = RuleMetadata(
        id="RULE-001",
        name="Suspicious Execution",
        description="Detects suspicious execution patterns",
        severity="HIGH",
        authors=("Detection Team",),
        mitre_attack={"execution": ("T1059.001",)},
        tags=("windows", "powershell"),
        references=("https://attack.mitre.org/techniques/T1059/001/",),
    )
    with pytest.raises(FrozenInstanceError):
        meta.name = "Modified Name"  # type: ignore[misc]


def test_rule_metadata_equality() -> None:
    meta1 = RuleMetadata(
        id="RULE-001",
        name="Rule 1",
        description="Desc",
        severity="LOW",
        authors=("Author",),
        mitre_attack={},
        tags=(),
        references=(),
    )
    meta2 = RuleMetadata(
        id="RULE-001",
        name="Rule 1",
        description="Desc",
        severity="LOW",
        authors=("Author",),
        mitre_attack={},
        tags=(),
        references=(),
    )
    assert meta1 == meta2


def test_rule_envelope_structure() -> None:
    meta = RuleMetadata(
        id="RULE-001",
        name="Suspicious PowerShell",
        description="Detects suspicious PowerShell command lines",
        severity="HIGH",
        authors=("SecOps",),
        mitre_attack={"execution": ("T1059.001",)},
        tags=("powershell",),
        references=(),
    )
    deployment = BaseDeploymentConfig(enabled=True, alerting=True)
    guide = InvestigationGuide(
        context="PowerShell execution with encoded arguments.",
        triage_runbook="Check parent process and decoded command.",
        false_positives=("Admin management scripts",),
        response_playbooks=("Isolate host",),
    )
    event = TestEvent(
        timestamp="2026-09-17T11:00:00Z",
        data={"target": {"process": {"command_line": "powershell -enc"}}},
    )
    test_vec = TestVector(
        name="Match on encoded PowerShell",
        description="Simulates encoded command invocation",
        events=(event,),
        expected_match=True,
    )
    rule_logic = (
        "rule powershell_encoded {\n"
        "  events:\n"
        '    $e.target.process.command_line = "powershell -enc"\n'
        "  condition:\n"
        "    $e\n"
        "}"
    )
    envelope = RuleEnvelope(
        metadata=meta,
        logic=rule_logic,
        deployment=deployment,
        guide=guide,
        test=(test_vec,),
    )

    assert envelope.metadata.id == "RULE-001"
    assert envelope.deployment.enabled is True
    assert len(envelope.test) == 1
    assert envelope.test[0].events[0].timestamp == "2026-09-17T11:00:00Z"
    with pytest.raises(FrozenInstanceError):
        envelope.logic = "new logic"  # type: ignore[misc]


def test_managed_state_immutability() -> None:
    dep = ManagedDeployment(type="PRECISE", enabled=True, alerting=True)
    ruleset = ManagedRuleSet(
        id="rs-cloud-threats",
        name="Cloud Threats",
        category="CLOUD",
        deployments=(dep,),
    )
    exclusion = ManagedExclusion(
        id="ex-1",
        rule_id="r-1",
        ruleset_id=None,
        expression='$e.principal.user.userid != "svc_backup"',
        description="Exclude backup service account",
    )
    state = ManagedState(rulesets=(ruleset,), exclusions=(exclusion,))

    assert state.rulesets[0].deployments[0].type == "PRECISE"
    assert len(state.exclusions) == 1
    with pytest.raises(FrozenInstanceError):
        state.rulesets = ()  # type: ignore[misc]


def test_compilation_result() -> None:
    diag = CompilationDiagnostic(
        line=4,
        column=12,
        message="Undefined event variable: $e",
        severity="ERROR",
    )
    res = CompilationResult(success=False, diagnostics=(diag,))
    assert res.success is False
    assert len(res.diagnostics) == 1
    assert res.diagnostics[0].line == 4
