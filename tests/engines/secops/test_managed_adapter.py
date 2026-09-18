from collections.abc import Mapping
from typing import Any

import pytest

from graft.core.models.managed import (
    ManagedDeployment,
    ManagedExclusion,
    ManagedRuleSet,
    ManagedState,
)
from graft.engines.secops.client import SecOpsClient
from graft.engines.secops.config import SecOpsConfig
from graft.engines.secops.managed import SecOpsManagedAdapter

INSTANCE_BASE = "projects/test-project/locations/us/instances/11111111-2222-3333-4444-555555555555"


class MockSecOpsClient(SecOpsClient):
    def __init__(self) -> None:
        config = SecOpsConfig(
            project="test-project",
            location="us",
            instance_id="11111111-2222-3333-4444-555555555555",
            service_account_email="sa@test.iam.gserviceaccount.com",
        )
        super().__init__(config=config)
        self.calls: list[dict[str, Any]] = []
        self.responses: dict[str, dict[str, object]] = {}

    def set_response(self, method: str, path: str, response: dict[str, object]) -> None:
        self.responses[f"{method.upper()} {path}"] = response

    def request(
        self,
        method: str,
        path: str,
        body: Mapping[str, object] | None = None,
        params: Mapping[str, str] | None = None,
        api_version: str | None = None,
    ) -> dict[str, object]:
        self.calls.append(
            {
                "method": method.upper(),
                "path": path,
                "body": dict(body) if body is not None else None,
                "params": dict(params) if params is not None else None,
                "api_version": api_version,
            }
        )
        key = f"{method.upper()} {path}"
        if key in self.responses:
            return self.responses[key]
        return {}


@pytest.fixture
def mock_client() -> MockSecOpsClient:
    return MockSecOpsClient()


@pytest.fixture
def adapter(mock_client: MockSecOpsClient) -> SecOpsManagedAdapter:
    return SecOpsManagedAdapter(client=mock_client)


def test_fetch_managed_state_success(
    mock_client: MockSecOpsClient, adapter: SecOpsManagedAdapter
) -> None:
    mock_client.set_response(
        "GET",
        "curatedRuleSetCategories/-/curatedRuleSets",
        {
            "curatedRuleSets": [
                {
                    "name": (
                        f"{INSTANCE_BASE}/curatedRuleSetCategories/cloud/curatedRuleSets/"
                        "rs-cloud-threats"
                    ),
                    "displayName": "Cloud Threat Detections",
                },
                {
                    "name": (
                        f"{INSTANCE_BASE}/curatedRuleSetCategories/endpoint/curatedRuleSets/"
                        "rs-linux-threats"
                    ),
                    "displayName": "Linux Threat Detections",
                },
            ]
        },
    )
    mock_client.set_response(
        "GET",
        "curatedRuleSetCategories/cloud/curatedRuleSets/rs-cloud-threats/curatedRuleSetDeployments",
        {
            "curatedRuleSetDeployments": [
                {
                    "name": ".../curatedRuleSetDeployments/precise",
                    "enabled": True,
                    "alerting": True,
                },
                {
                    "name": ".../curatedRuleSetDeployments/broad",
                    "enabled": False,
                    "alerting": False,
                },
            ]
        },
    )
    mock_client.set_response(
        "GET",
        "curatedRuleSetCategories/endpoint/curatedRuleSets/rs-linux-threats/curatedRuleSetDeployments",
        {
            "curatedRuleSetDeployments": [
                {
                    "name": ".../curatedRuleSetDeployments/precise",
                    "enabled": True,
                    "alerting": True,
                },
                {
                    "name": ".../curatedRuleSetDeployments/broad",
                    "enabled": False,
                    "alerting": False,
                },
            ]
        },
    )
    mock_client.set_response(
        "GET",
        "findingsRefinements",
        {
            "findingsRefinements": [
                {
                    "name": f"{INSTANCE_BASE}/findingsRefinements/ex-backup-service-account",
                    "displayName": "Exclude scheduled backup",
                    "query": '$e.principal.user.userid != "svc_backup"',
                    "appliedCuratedRuleSets": [
                        f"{INSTANCE_BASE}/curatedRuleSetCategories/cloud/curatedRuleSets/rs-cloud-threats"
                    ],
                    "appliedDetectionRules": ["ru_cloud_iam_privilege_escalation"],
                }
            ]
        },
    )

    state = adapter.fetch_managed_state()

    assert len(state.rulesets) == 2
    rs1 = state.rulesets[0]
    assert rs1.id == "rs-cloud-threats"
    assert rs1.name == "Cloud Threat Detections"
    assert rs1.category == "cloud"
    assert len(rs1.deployments) == 2
    assert rs1.deployments[0] == ManagedDeployment(type="PRECISE", enabled=True, alerting=True)
    assert rs1.deployments[1] == ManagedDeployment(type="BROAD", enabled=False, alerting=False)

    assert len(state.exclusions) == 1
    ex = state.exclusions[0]
    assert ex.id == "ex-backup-service-account"
    assert ex.rule_id == "ru_cloud_iam_privilege_escalation"
    assert ex.ruleset_id == "rs-cloud-threats"
    assert ex.expression == '$e.principal.user.userid != "svc_backup"'
    assert ex.description == "Exclude scheduled backup"


def test_set_ruleset_deployment(
    mock_client: MockSecOpsClient, adapter: SecOpsManagedAdapter
) -> None:
    adapter.set_ruleset_deployment(
        ruleset_id="rs-cloud-threats",
        deployment_type="PRECISE",
        enabled=False,
        alerting=False,
        category="cloud",
    )

    expected_path = (
        "curatedRuleSetCategories/cloud/curatedRuleSets/rs-cloud-threats/"
        "curatedRuleSetDeployments/precise"
    )
    assert len(mock_client.calls) == 1
    call = mock_client.calls[0]
    assert call["method"] == "PATCH"
    assert call["path"] == expected_path
    assert call["body"] == {"enabled": False, "alerting": False}
    assert call["params"] == {"update_mask": "enabled,alerting"}


def test_create_exclusion(mock_client: MockSecOpsClient, adapter: SecOpsManagedAdapter) -> None:
    exclusion = ManagedExclusion(
        id="ex-new",
        rule_id="ru_iam",
        ruleset_id="rs-cloud-threats",
        expression='$e.principal.ip != "10.0.0.1"',
        description="Ignore test IP",
    )
    result_id = adapter.create_exclusion(exclusion)

    assert result_id == "ex-new"
    assert len(mock_client.calls) == 1
    call = mock_client.calls[0]
    assert call["method"] == "POST"
    assert call["path"] == "findingsRefinements"
    assert call["params"] == {"findings_refinement_id": "ex-new"}
    assert call["body"] is not None
    assert call["body"]["displayName"] == "Ignore test IP"
    assert call["body"]["query"] == '$e.principal.ip != "10.0.0.1"'
    assert call["body"]["appliedDetectionRules"] == ["ru_iam"]
    assert "rs-cloud-threats" in str(call["body"]["appliedCuratedRuleSets"])


def test_update_exclusion(mock_client: MockSecOpsClient, adapter: SecOpsManagedAdapter) -> None:
    exclusion = ManagedExclusion(
        id="ex-existing",
        rule_id=None,
        ruleset_id="rs-cloud-threats",
        expression='$e.principal.ip != "10.0.0.2"',
        description="Updated IP",
    )
    adapter.update_exclusion(exclusion)

    assert len(mock_client.calls) == 1
    call = mock_client.calls[0]
    assert call["method"] == "PATCH"
    assert call["path"] == "findingsRefinements/ex-existing"
    assert call["params"] == {
        "update_mask": "displayName,query,appliedCuratedRuleSets,appliedDetectionRules"
    }
    assert call["body"] is not None
    assert call["body"]["displayName"] == "Updated IP"
    assert call["body"]["query"] == '$e.principal.ip != "10.0.0.2"'


def test_delete_exclusion(mock_client: MockSecOpsClient, adapter: SecOpsManagedAdapter) -> None:
    adapter.delete_exclusion("ex-old")

    assert len(mock_client.calls) == 1
    call = mock_client.calls[0]
    assert call["method"] == "DELETE"
    assert call["path"] == "findingsRefinements/ex-old"


def test_apply_managed_state_orchestration(
    mock_client: MockSecOpsClient, adapter: SecOpsManagedAdapter
) -> None:
    mock_client.set_response(
        "GET",
        "curatedRuleSetCategories/-/curatedRuleSets",
        {
            "curatedRuleSets": [
                {
                    "name": (
                        f"{INSTANCE_BASE}/curatedRuleSetCategories/cloud/curatedRuleSets/rs-cloud"
                    ),
                    "displayName": "Cloud Threats",
                }
            ]
        },
    )
    mock_client.set_response(
        "GET",
        "curatedRuleSetCategories/cloud/curatedRuleSets/rs-cloud/curatedRuleSetDeployments",
        {
            "curatedRuleSetDeployments": [
                {"name": ".../precise", "enabled": False, "alerting": False},
                {"name": ".../broad", "enabled": False, "alerting": False},
            ]
        },
    )
    mock_client.set_response("GET", "findingsRefinements", {"findingsRefinements": []})

    desired_state = ManagedState(
        rulesets=(
            ManagedRuleSet(
                id="rs-cloud",
                name="Cloud Threats",
                category="cloud",
                deployments=(
                    ManagedDeployment(type="PRECISE", enabled=True, alerting=True),
                    ManagedDeployment(type="BROAD", enabled=False, alerting=False),
                ),
            ),
        ),
        exclusions=(),
    )

    adapter.apply_managed_state(desired_state)

    expected_path = (
        "curatedRuleSetCategories/cloud/curatedRuleSets/rs-cloud/curatedRuleSetDeployments/precise"
    )
    patch_calls = [c for c in mock_client.calls if c["method"] == "PATCH"]
    assert len(patch_calls) == 1
    assert patch_calls[0]["path"] == expected_path
    assert patch_calls[0]["body"] == {"enabled": True, "alerting": True}


def test_fetch_managed_state_bulk_deployments(
    mock_client: MockSecOpsClient, adapter: SecOpsManagedAdapter
) -> None:
    mock_client.set_response(
        "GET",
        "curatedRuleSetCategories/-/curatedRuleSets",
        {
            "curatedRuleSets": [
                {
                    "name": (
                        f"{INSTANCE_BASE}/curatedRuleSetCategories/cloud/curatedRuleSets/"
                        "rs-bulk-test"
                    ),
                    "displayName": "Bulk Test Ruleset",
                }
            ]
        },
    )
    mock_client.set_response(
        "GET",
        "curatedRuleSetCategories/-/curatedRuleSets/-/curatedRuleSetDeployments",
        {
            "curatedRuleSetDeployments": [
                {
                    "name": (
                        f"{INSTANCE_BASE}/curatedRuleSetCategories/cloud/curatedRuleSets/"
                        "rs-bulk-test/curatedRuleSetDeployments/precise"
                    ),
                    "precision": "PRECISE",
                    "enabled": True,
                    "alerting": True,
                },
                {
                    "name": (
                        f"{INSTANCE_BASE}/curatedRuleSetCategories/cloud/curatedRuleSets/"
                        "rs-bulk-test/curatedRuleSetDeployments/broad"
                    ),
                    "precision": "BROAD",
                    "enabled": False,
                    "alerting": False,
                },
            ]
        },
    )
    mock_client.set_response("GET", "findingsRefinements", {"findingsRefinements": []})

    state = adapter.fetch_managed_state()

    assert len(state.rulesets) == 1
    rs = state.rulesets[0]
    assert rs.id == "rs-bulk-test"
    assert len(rs.deployments) == 2
    assert rs.deployments[0] == ManagedDeployment(type="PRECISE", enabled=True, alerting=True)
    assert rs.deployments[1] == ManagedDeployment(type="BROAD", enabled=False, alerting=False)
