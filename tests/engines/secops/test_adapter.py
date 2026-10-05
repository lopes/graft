from unittest.mock import MagicMock

import pytest

from graft.core.ports.engine import EngineAdapter
from graft.engines.secops.adapter import SecOpsAdapter, secops_rule_content_matches
from graft.engines.secops.client import SecOpsClient


def test_secops_adapter_protocol_conformance() -> None:
    adapter = SecOpsAdapter(env="staging")
    assert isinstance(adapter, EngineAdapter)


def test_secops_adapter_with_mock_client() -> None:
    mock_client = MagicMock(spec=SecOpsClient)
    adapter = SecOpsAdapter(env="production", client=mock_client)

    assert adapter.get_compiler() is not None
    assert adapter.get_deployer() is not None
    assert adapter.get_managed() is not None
    assert adapter.get_replay() is not None


def test_secops_adapter_without_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    monkeypatch.setattr(os, "environ", {})

    adapter = SecOpsAdapter(env="production")
    # Adapters are initialized with mock config so CLI/tests don't crash on instantiation,
    # but replay correctly reports unavailable.
    assert adapter.get_compiler() is not None
    assert adapter.get_deployer() is not None
    assert adapter.get_managed() is not None
    replay = adapter.get_replay()
    assert replay is not None
    assert replay.is_available() is False


def test_secops_adapter_are_rules_equal() -> None:
    from graft.core.models.rule import BaseDeploymentConfig, RuleEnvelope, RuleMetadata, Runbook

    meta = RuleMetadata(
        id="c4e9b8f2-89b1-4f81-9b16-928d54128f73",
        name="test_rule",
        description="desc",
    )
    rule = RuleEnvelope(
        metadata=meta,
        logic="events:\n  $e.metadata.event_type = 'USER_LOGIN'\ncondition:\n  $e",
        deployment=BaseDeploymentConfig(enabled=True, alerting=True),
        runbook=Runbook(context="c", triage="t", response="r"),
        tests=(),
    )

    adapter = SecOpsAdapter()
    assert adapter.are_rules_equal(rule, rule) is True
    assert secops_rule_content_matches(rule, rule) is True


def test_secops_adapter_resolve_deployment_status() -> None:
    from graft.core.models.rule import BaseDeploymentConfig, RuleEnvelope, RuleMetadata, Runbook

    meta = RuleMetadata(
        id="c4e9b8f2-89b1-4f81-9b16-928d54128f73",
        name="test_rule",
        description="d",
    )
    runbook = Runbook(context="c", triage="t", response="r")

    adapter = SecOpsAdapter()

    rule_enabled = RuleEnvelope(
        metadata=meta,
        logic="events: $e condition: $e",
        deployment=BaseDeploymentConfig(enabled=True, alerting=True),
        runbook=runbook,
        tests=(),
    )
    rule_silent = RuleEnvelope(
        metadata=meta,
        logic="events: $e condition: $e",
        deployment=BaseDeploymentConfig(enabled=True, alerting=False),
        runbook=runbook,
        tests=(),
    )
    rule_disabled = RuleEnvelope(
        metadata=meta,
        logic="events: $e condition: $e",
        deployment=BaseDeploymentConfig(enabled=False, alerting=False),
        runbook=runbook,
        tests=(),
    )

    assert adapter.resolve_deployment_status(rule_enabled) == "enabled"
    assert adapter.resolve_deployment_status(rule_silent) == "silent"
    assert adapter.resolve_deployment_status(rule_disabled) == "disabled"


def test_secops_adapter_managed_rule_validation_and_status_resolution() -> None:
    from graft.core.models.managed import ManagedDeployment, ManagedRuleSet, ManagedState
    from graft.core.models.rule import ManagedRuleRef, RuleEnvelope, RuleMetadata, Runbook

    state = ManagedState(
        rulesets=(
            ManagedRuleSet(
                id="rs-enabled",
                name="Enabled Ruleset",
                category="Cloud",
                deployments=(
                    ManagedDeployment(type="PRECISE", enabled=True, alerting=True),
                    ManagedDeployment(type="BROAD", enabled=False, alerting=False),
                ),
            ),
            ManagedRuleSet(
                id="rs-silent",
                name="Silent Ruleset",
                category="Cloud",
                deployments=(
                    ManagedDeployment(type="PRECISE", enabled=True, alerting=False),
                    ManagedDeployment(type="BROAD", enabled=True, alerting=False),
                ),
            ),
            ManagedRuleSet(
                id="rs-disabled",
                name="Disabled Ruleset",
                category="Cloud",
                deployments=(
                    ManagedDeployment(type="PRECISE", enabled=False, alerting=False),
                    ManagedDeployment(type="BROAD", enabled=False, alerting=False),
                ),
            ),
        )
    )

    adapter = SecOpsAdapter()
    assert adapter.has_managed_rule_id("rs-enabled", state) is True
    assert adapter.has_managed_rule_id("rs-missing", state) is False

    def _make_managed(mid: str) -> RuleEnvelope:
        return RuleEnvelope(
            metadata=RuleMetadata(
                id="c4e9b8f2-89b1-4f81-9b16-928d54128f73", name="m", description="d"
            ),
            runbook=Runbook(context="c", triage="t", response="r"),
            managed=ManagedRuleRef(id=mid),
        )

    assert adapter.resolve_deployment_status(_make_managed("rs-enabled"), state) == "enabled"
    assert adapter.resolve_deployment_status(_make_managed("rs-silent"), state) == "silent"
    assert adapter.resolve_deployment_status(_make_managed("rs-disabled"), state) == "disabled"
    assert adapter.resolve_deployment_status(_make_managed("rs-missing"), state) == "disabled"
    assert adapter.resolve_deployment_status(_make_managed("rs-enabled"), None) == "disabled"


def test_secops_adapter_default_rule_logic() -> None:
    adapter = SecOpsAdapter()
    logic = adapter.get_default_rule_logic("suspicious_login")
    assert "$e.metadata.event_type" in logic
    assert "condition:" in logic


def test_secops_adapter_validate_rule_dataset_references() -> None:
    from graft.core.models.rule import BaseDeploymentConfig, RuleEnvelope, RuleMetadata, Runbook

    adapter = SecOpsAdapter()

    def _rule_with_logic(logic: str) -> RuleEnvelope:
        return RuleEnvelope(
            metadata=RuleMetadata(
                id="c4e9b8f2-89b1-4f81-9b16-928d54128f73",
                name="scanner_rule",
                description="desc",
            ),
            logic=logic,
            deployment=BaseDeploymentConfig(enabled=True, alerting=True),
            runbook=Runbook(context="c", triage="t", response="r"),
            tests=(),
        )

    adapter.validate_rule_dataset_references(
        _rule_with_logic(
            "events:\n  $e.principal.ip in %known_scanner_ips.value\n"
            "  // $e.principal.ip in cidr %known_scanner_ips\n"
            "  /* $e.principal.ip in %known_scanner_ips.ip */\n"
            "condition:\n  $e"
        ),
        {"known_scanner_ips"},
    )

    with pytest.raises(ValueError, match=r"must be referenced as '%known_scanner_ips\.value'"):
        adapter.validate_rule_dataset_references(
            _rule_with_logic(
                "events:\n  $e.principal.ip in %known_scanner_ips.ip\ncondition:\n  $e"
            ),
            {"known_scanner_ips"},
        )

    with pytest.raises(ValueError, match="uses 'in cidr' with local dataset"):
        adapter.validate_rule_dataset_references(
            _rule_with_logic(
                "events:\n  $e.principal.ip in cidr %known_scanner_ips.value\ncondition:\n  $e"
            ),
            {"known_scanner_ips"},
        )

    with pytest.raises(ValueError, match="uses 'in regex' with local dataset"):
        adapter.validate_rule_dataset_references(
            _rule_with_logic(
                "events:\n"
                "  $e.principal.hostname in regex %known_scanner_ips.value\n"
                "condition:\n  $e"
            ),
            {"known_scanner_ips"},
        )
