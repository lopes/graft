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
