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
        owners=("Detection Engineering",),
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
    assert envelope.metadata.owners == ("Detection Engineering",)
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


def test_managed_rule_envelope_structure() -> None:
    from graft.core.models.rule import ManagedRuleRef

    meta = RuleMetadata(
        id="c4e9b8f2-89b1-4f81-9b16-928d54128f73",
        name="curated_suspicious_exec",
        description="Registers Malware Signals curated ruleset",
        owners=("Detection Engineering",),
        mitre={"execution": ("T1059.001",)},
        tags=("siem_alpha", "managed"),
        references=("https://attack.mitre.org/techniques/T1059/001/",),
    )
    managed_ref = ManagedRuleRef(id="1c4ab1f6-d801-d6a9-1177-3ec3dd5bcbe9")
    runbook = Runbook(
        context="Curated ruleset detecting suspicious execution.",
        triage="1. Review process tree.",
        response="1. Isolate host.",
    )
    envelope = RuleEnvelope(
        metadata=meta,
        runbook=runbook,
        tests=(),
        managed=managed_ref,
    )

    assert envelope.is_managed is True
    assert envelope.rule_type == "managed"
    assert envelope.managed is not None
    assert envelope.managed.id == "1c4ab1f6-d801-d6a9-1177-3ec3dd5bcbe9"
    assert envelope.logic == ""
    with pytest.raises(FrozenInstanceError):
        envelope.managed = ManagedRuleRef(id="other")  # type: ignore[misc]
