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
    assert first_call[1]["params"] == {"update_mask": "text"}


def test_list_rules_with_deployments_success(mock_client: MagicMock) -> None:
    mock_client.request.side_effect = [
        {
            "rules": [
                {
                    "name": "projects/p/locations/l/instances/i/rules/ru_12345",
                    "displayName": "custom_login_detection",
                    "text": "rule custom_login_detection { condition: true }",
                },
            ],
        },
        {
            "ruleDeployments": [
                {
                    "name": "projects/p/locations/l/instances/i/rules/ru_12345/deployment",
                    "enabled": True,
                    "alerting": True,
                },
            ],
        },
    ]

    deployer = SecOpsDeployerAdapter(client=mock_client)
    rules = deployer.list_rules()

    assert len(rules) == 1
    rule = rules[0]
    assert rule.metadata.id == "ru_12345"
    assert rule.metadata.name == "custom_login_detection"
    assert rule.logic == "rule custom_login_detection { condition: true }"
    assert rule.deployment.enabled is True
    assert rule.deployment.alerting is True

    assert mock_client.request.call_count == 2
    first_call = mock_client.request.call_args_list[0]
    assert first_call[0] == ("GET", "rules")
    assert first_call[1]["params"] == {"view": "FULL", "pageSize": "100"}

    second_call = mock_client.request.call_args_list[1]
    assert second_call[0] == ("GET", "rules/-/deployments")


def test_list_rules_deployments_fallback_on_api_error(mock_client: MagicMock) -> None:
    from graft.engines.secops.client import SecOpsApiError

    mock_client.request.side_effect = [
        {
            "rules": [
                {
                    "name": "projects/p/locations/l/instances/i/rules/ru_12345",
                    "displayName": "custom_login_detection",
                    "text": "rule custom_login_detection { condition: true }",
                },
            ],
        },
        SecOpsApiError("Not found", 404),
    ]

    deployer = SecOpsDeployerAdapter(client=mock_client)
    rules = deployer.list_rules()

    assert len(rules) == 1
    rule = rules[0]
    assert rule.metadata.id == "ru_12345"
    assert rule.deployment.enabled is False
    assert rule.deployment.alerting is False


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


def test_list_rules_extracts_graft_uuid_from_meta_id(mock_client: MagicMock) -> None:
    graft_uuid = "b1d72370-5fa3-4cb8-a579-22a468d6f101"
    yaral_text = f"""rule custom_login_detection {{
  meta:
    id = "{graft_uuid}"
    description = "Test rule"
  events:
    $e.metadata.event_type = "USER_LOGIN"
  condition:
    $e
}}"""
    mock_client.request.side_effect = [
        {
            "rules": [
                {
                    "name": "projects/p/locations/l/instances/i/rules/ru_remote_99999",
                    "displayName": "custom_login_detection",
                    "text": yaral_text,
                },
            ],
        },
        {"ruleDeployments": []},
    ]

    deployer = SecOpsDeployerAdapter(client=mock_client)
    rules = deployer.list_rules()

    assert len(rules) == 1
    assert rules[0].metadata.id == graft_uuid
    assert rules[0].metadata.name == "custom_login_detection"


def test_update_rule_resolves_remote_id_and_preserves_meta_id(
    mock_client: MagicMock, sample_rule: RuleEnvelope
) -> None:
    # RuleEnvelope with Graft UUID
    graft_uuid = "b1d72370-5fa3-4cb8-a579-22a468d6f101"
    import dataclasses

    rule_to_update = dataclasses.replace(
        sample_rule,
        metadata=dataclasses.replace(
            sample_rule.metadata,
            id=graft_uuid,
            name="test_rule",
        ),
    )

    mock_client.request.side_effect = [
        # 1. GET rules (list_rules)
        {
            "rules": [
                {
                    "name": "projects/p/locations/l/instances/i/rules/ru_secops_555",
                    "displayName": "test_rule",
                    "text": "rule test_rule { condition: true }",
                }
            ]
        },
        # 2. GET rules/-/deployments
        {"ruleDeployments": []},
        # 3. PATCH rules/ru_secops_555 (rule text)
        {"name": "projects/p/locations/l/instances/i/rules/ru_secops_555"},
        # 4. PATCH rules/ru_secops_555/deployment
        {"name": "projects/p/locations/l/instances/i/rules/ru_secops_555/deployment"},
    ]

    deployer = SecOpsDeployerAdapter(client=mock_client)
    deployer.list_rules()
    deployer.update_rule(rule_to_update)

    assert mock_client.request.call_count == 4
    patch_text_call = mock_client.request.call_args_list[2]
    assert patch_text_call[0] == ("PATCH", "rules/ru_secops_555")
    sent_text = patch_text_call[1]["body"]["text"]
    # Verify Graft UUID is preserved in meta.id and ru_secops_555 is NOT in meta.id
    assert f'id = "{graft_uuid}"' in sent_text
    assert "ru_secops_555" not in sent_text


def test_list_rules_with_pagination_fetches_all_pages(mock_client: MagicMock) -> None:
    mock_client.request.side_effect = [
        # Rules page 1
        {
            "rules": [
                {
                    "name": "projects/p/locations/l/instances/i/rules/ru_page1",
                    "displayName": "rule_one",
                    "text": "rule rule_one { condition: true }",
                }
            ],
            "nextPageToken": "token_page_2",
        },
        # Rules page 2
        {
            "rules": [
                {
                    "name": "projects/p/locations/l/instances/i/rules/ru_page2",
                    "displayName": "rule_two",
                    "text": "rule rule_two { condition: true }",
                }
            ],
        },
        # Deployments page 1
        {
            "ruleDeployments": [
                {
                    "name": "projects/p/locations/l/instances/i/rules/ru_page1/deployment",
                    "enabled": True,
                    "alerting": True,
                }
            ],
            "nextPageToken": "dep_token_page_2",
        },
        # Deployments page 2
        {
            "ruleDeployments": [
                {
                    "name": "projects/p/locations/l/instances/i/rules/ru_page2/deployment",
                    "enabled": False,
                    "alerting": False,
                }
            ],
        },
    ]

    deployer = SecOpsDeployerAdapter(client=mock_client)
    rules = deployer.list_rules()

    assert len(rules) == 2
    assert rules[0].metadata.name == "rule_one"
    assert rules[0].deployment.enabled is True
    assert rules[1].metadata.name == "rule_two"
    assert rules[1].deployment.enabled is False
    assert mock_client.request.call_count == 4


def test_create_rule_logs_warning_when_deployment_step_fails(
    mock_client: MagicMock, sample_rule: RuleEnvelope, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    from graft.engines.secops.client import SecOpsApiError

    mock_client.request.side_effect = [
        {"name": "projects/p/locations/l/instances/i/rules/ru_created_999"},
        SecOpsApiError(
            "Permission denied on deployment",
            403,
            status="PERMISSION_DENIED",
            method="PATCH",
            path="rules/ru_created_999/deployment",
        ),
    ]

    deployer = SecOpsDeployerAdapter(client=mock_client)
    with (
        caplog.at_level(logging.DEBUG, logger="graft.secops.deployer"),
        pytest.raises(SecOpsApiError),
    ):
        deployer.create_rule(sample_rule)

    warnings = [r.message for r in caplog.records if r.levelname == "WARNING"]
    assert any(
        "Rule 'test_rule' was created on tenant (id=ru_created_999), but setting deployment state"
        in msg
        for msg in warnings
    )


def test_update_rule_logs_warning_when_deployment_step_fails(
    mock_client: MagicMock, sample_rule: RuleEnvelope, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    from graft.engines.secops.client import SecOpsApiError

    rule_id = sample_rule.metadata.id
    mock_client.request.side_effect = [
        {"name": f"projects/p/locations/l/instances/i/rules/{rule_id}"},
        SecOpsApiError(
            "Invalid deployment state",
            400,
            status="INVALID_ARGUMENT",
            method="PATCH",
            path=f"rules/{rule_id}/deployment",
        ),
    ]

    deployer = SecOpsDeployerAdapter(client=mock_client)
    with (
        caplog.at_level(logging.DEBUG, logger="graft.secops.deployer"),
        pytest.raises(SecOpsApiError),
    ):
        deployer.update_rule(sample_rule)

    warnings = [r.message for r in caplog.records if r.levelname == "WARNING"]
    assert any(
        f"Rule 'test_rule' logic was updated on tenant (id={rule_id}), but setting deployment state"
        in msg
        for msg in warnings
    )
