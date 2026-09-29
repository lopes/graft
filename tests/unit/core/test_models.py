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
    RuleEnvelope,
    RuleMetadata,
    Runbook,
    TestEvent,
    TestVector,
)


def test_rule_metadata_immutability() -> None:
    meta = RuleMetadata(
        id="c4e9b8f2-89b1-4f81-9b16-928d54128f73",
        name="powershell_encoded_launch",
        description="Detects suspicious execution patterns",
        owners=("Detection Team",),
        mitre={"execution": ("T1059.001",)},
        tags=("windows", "powershell"),
        references=("https://attack.mitre.org/techniques/T1059/001/",),
    )
    assert not hasattr(meta, "priority")
    assert not hasattr(meta, "authors")
    with pytest.raises(FrozenInstanceError):
        meta.name = "modified_name"  # type: ignore[misc]


def test_rule_metadata_equality_and_defaults() -> None:
    meta1 = RuleMetadata(
        id="c4e9b8f2-89b1-4f81-9b16-928d54128f73",
        name="rule_test",
        description="Desc",
        owners=("Owner",),
    )
    meta2 = RuleMetadata(
        id="c4e9b8f2-89b1-4f81-9b16-928d54128f73",
        name="rule_test",
        description="Desc",
        owners=("Owner",),
    )
    assert meta1 == meta2
    assert meta1.owners == ("Owner",)
    assert meta1.mitre == {}
    assert meta1.tags == ()
    assert meta1.references == ()


def test_rule_envelope_structure() -> None:
    meta = RuleMetadata(
        id="c4e9b8f2-89b1-4f81-9b16-928d54128f73",
        name="powershell_encoded",
        description="Detects suspicious PowerShell command lines",
        owners=("SecOps",),
        mitre={"execution": ("T1059.001",)},
        tags=("powershell",),
        references=("Internal Threat Research",),
    )
    deployment = BaseDeploymentConfig(enabled=True, alerting=True, run_frequency="live")
    runbook = Runbook(
        context="PowerShell execution with base64 encoded arguments.",
        triage="1. Decode command.\n2. Check parent process.\n3. If admin script, verify hash.",
        response="1. Isolate host.\n2. Revoke user sessions.",
    )
    event = TestEvent(
        timestamp="2026-09-17T11:00:00Z",
        payload={"target": {"process": {"command_line": "powershell -enc"}}},
    )
    test_vec = TestVector(
        id="match_encoded_command",
        description="Simulates encoded command invocation",
        events=(event,),
        expect=1,
    )
    rule_logic = 'events:\n  $e.target.process.command_line = "powershell -enc"\ncondition:\n  $e\n'
    envelope = RuleEnvelope(
        metadata=meta,
        logic=rule_logic,
        deployment=deployment,
        runbook=runbook,
        tests=(test_vec,),
    )

    assert envelope.metadata.id == "c4e9b8f2-89b1-4f81-9b16-928d54128f73"
    assert envelope.metadata.owners == ("SecOps",)
    assert envelope.deployment.enabled is True
    assert envelope.deployment.run_frequency == "live"
    assert envelope.runbook.triage.startswith("1. Decode")
    assert len(envelope.tests) == 1
    assert envelope.tests[0].id == "match_encoded_command"
    assert envelope.tests[0].expect == 1
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
