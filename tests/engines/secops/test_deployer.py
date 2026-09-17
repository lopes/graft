from unittest.mock import MagicMock

import pytest

from graft.core.models.rule import BaseDeploymentConfig, RuleEnvelope, RuleMetadata, Runbook
from graft.engines.secops.client import SecOpsClient
from graft.engines.secops.deployer import SecOpsDeployerAdapter


@pytest.fixture
def mock_client() -> MagicMock:
    return MagicMock(spec=SecOpsClient)


@pytest.fixture
def sample_rule() -> RuleEnvelope:
    metadata = RuleMetadata(
        id="ru_11111111-2222-3333-4444-555555555555",
        name="test_rule",
        description="Test rule description",
        status="production",
        authors=("Detection Engineer",),
        mitre={"execution": ("T1059.001",)},
    )
    logic = 'events:\n  $e.metadata.event_type = "PROCESS_LAUNCH"\ncondition:\n  $e'
    runbook = Runbook(context="ctx", triage="trg", response="rsp")
    deployment = BaseDeploymentConfig(enabled=True, alerting=False)
    return RuleEnvelope(
        metadata=metadata,
        logic=logic,
        deployment=deployment,
        runbook=runbook,
        tests=(),
    )


def test_create_rule_success(mock_client: MagicMock, sample_rule: RuleEnvelope) -> None:
    mock_client.request.side_effect = [
        {"name": "projects/p/locations/l/instances/i/rules/ru_12345"},
        {
            "name": "projects/p/locations/l/instances/i/rules/ru_12345/deployment",
            "enabled": True,
            "alerting": False,
        },
    ]

    deployer = SecOpsDeployerAdapter(client=mock_client)
    rule_id = deployer.create_rule(sample_rule)

    assert rule_id == "ru_12345"
    assert mock_client.request.call_count == 2
    first_call = mock_client.request.call_args_list[0]
    assert first_call[0][0] == "POST"
    assert first_call[0][1] == "rules"
    assert "rule test_rule {" in first_call[1]["body"]["text"]

    second_call = mock_client.request.call_args_list[1]
    assert second_call[0][0] == "PATCH"
    assert second_call[0][1] == "rules/ru_12345/deployment"
    assert second_call[1]["body"] == {"enabled": True, "alerting": False}
    assert second_call[1]["params"] == {"update_mask": "enabled,alerting"}


def test_update_rule_success(mock_client: MagicMock, sample_rule: RuleEnvelope) -> None:
    rule_id = sample_rule.metadata.id
    mock_client.request.side_effect = [
        {"name": f"projects/p/locations/l/instances/i/rules/{rule_id}"},
        {"name": f"projects/p/locations/l/instances/i/rules/{rule_id}/deployment"},
    ]

    deployer = SecOpsDeployerAdapter(client=mock_client)
    deployer.update_rule(sample_rule)

    assert mock_client.request.call_count == 2
    first_call = mock_client.request.call_args_list[0]
    assert first_call[0][0] == "PATCH"
    assert first_call[0][1] == f"rules/{rule_id}"


def test_delete_rule_success(mock_client: MagicMock) -> None:
    mock_client.request.return_value = {}

    deployer = SecOpsDeployerAdapter(client=mock_client)
    deployer.delete_rule("ru_12345")

    mock_client.request.assert_called_once_with("DELETE", "rules/ru_12345")


def test_set_rule_state_success(mock_client: MagicMock) -> None:
    mock_client.request.return_value = {"enabled": True, "alerting": True}

    deployer = SecOpsDeployerAdapter(client=mock_client)
    deployer.set_rule_state("ru_12345", enabled=True, alerting=True)

    mock_client.request.assert_called_once_with(
        "PATCH",
        "rules/ru_12345/deployment",
        body={"enabled": True, "alerting": True},
        params={"update_mask": "enabled,alerting"},
    )
