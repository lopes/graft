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
                },
                {
                    "name": f"{INSTANCE_BASE}/findingsRefinements/ex-archived-rule",
                    "displayName": "Archived exclusion",
                    "query": '$e.principal.user.userid = "retired"',
                },
            ]
        },
    )
    dep_name_1 = f"{INSTANCE_BASE}/findingsRefinements/ex-backup-service-account/deployment"
    dep_name_2 = f"{INSTANCE_BASE}/findingsRefinements/ex-archived-rule/deployment"
    curated_rs = f"{INSTANCE_BASE}/curatedRuleSetCategories/cloud/curatedRuleSets/rs-cloud-threats"
    mock_client.set_response(
        "GET",
        ":listAllFindingsRefinementDeployments",
        {
            "allFindingsRefinementDeployments": [
                {
                    "name": dep_name_1,
                    "enabled": True,
                    "archived": False,
                    "detectionExclusionApplication": {
                        "curatedRuleSets": [curated_rs],
                        "rules": [f"{INSTANCE_BASE}/rules/ru_cloud_iam_privilege_escalation"],
                    },
                },
                {
                    "name": dep_name_2,
                    "enabled": False,
                    "archived": True,
                    "detectionExclusionApplication": {},
                },
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

    # Only active, non-archived exclusions should be returned
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
    mock_client.set_response(
        "POST",
        "findingsRefinements",
        {
            "name": f"{INSTANCE_BASE}/findingsRefinements/fr_server_generated_uuid",
            "displayName": "Ignore test IP",
            "query": '$e.principal.ip != "10.0.0.1"',
        },
    )
    exclusion = ManagedExclusion(
        id="ex-new",
        rule_id="ru_iam",
        ruleset_id="rs-cloud-threats",
        expression='$e.principal.ip != "10.0.0.1"',
        description="Ignore test IP",
    )
    result_id = adapter.create_exclusion(exclusion)

    assert result_id == "fr_server_generated_uuid"
    assert len(mock_client.calls) == 2

    # Call 1: create refinement
    call1 = mock_client.calls[0]
    assert call1["method"] == "POST"
    assert call1["path"] == "findingsRefinements"
    assert call1["params"] is None
    assert call1["body"] is not None
    assert call1["body"]["displayName"] == "Ignore test IP"
    assert call1["body"]["query"] == '$e.principal.ip != "10.0.0.1"'
    assert call1["body"]["type"] == "DETECTION_EXCLUSION"

    # Call 2: patch refinement deployment
    call2 = mock_client.calls[1]
    assert call2["method"] == "PATCH"
    assert call2["path"] == "findingsRefinements/fr_server_generated_uuid/deployment"
    assert call2["params"] == {"updateMask": "enabled,archived,detectionExclusionApplication"}
    assert call2["body"] is not None
    assert call2["body"]["enabled"] is True
    assert call2["body"]["archived"] is False
    app = call2["body"]["detectionExclusionApplication"]
    assert "rs-cloud-threats" in str(app["curatedRuleSets"])
    assert "ru_iam" in str(app["rules"])


def test_update_exclusion(mock_client: MockSecOpsClient, adapter: SecOpsManagedAdapter) -> None:
    exclusion = ManagedExclusion(
        id="ex-existing",
        rule_id=None,
        ruleset_id="rs-cloud-threats",
        expression='$e.principal.ip != "10.0.0.2"',
        description="Updated IP",
    )
    adapter.update_exclusion(exclusion)

    assert len(mock_client.calls) == 2

    # Call 1: patch refinement
    call1 = mock_client.calls[0]
    assert call1["method"] == "PATCH"
    assert call1["path"] == "findingsRefinements/ex-existing"
    assert call1["params"] == {"updateMask": "displayName,query"}
    assert call1["body"] is not None
    assert call1["body"]["displayName"] == "Updated IP"
    assert call1["body"]["query"] == '$e.principal.ip != "10.0.0.2"'

    # Call 2: patch deployment
    call2 = mock_client.calls[1]
    assert call2["method"] == "PATCH"
    assert call2["path"] == "findingsRefinements/ex-existing/deployment"
    assert call2["params"] == {"updateMask": "enabled,archived,detectionExclusionApplication"}
    assert call2["body"] is not None
    assert call2["body"]["enabled"] is True
    assert call2["body"]["archived"] is False
    app = call2["body"]["detectionExclusionApplication"]
    assert "rs-cloud-threats" in str(app["curatedRuleSets"])


def test_delete_exclusion(mock_client: MockSecOpsClient, adapter: SecOpsManagedAdapter) -> None:
    adapter.delete_exclusion("ex-old")

    assert len(mock_client.calls) == 1
    call = mock_client.calls[0]
    # Delete in SecOps archives the refinement deployment
    assert call["method"] == "PATCH"
    assert call["path"] == "findingsRefinements/ex-old/deployment"
    assert call["params"] == {"updateMask": "enabled,archived"}
    assert call["body"] == {"enabled": False, "archived": True}


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


def test_set_ruleset_deployment_resolves_category_from_cache_when_display_name_passed(
    mock_client: MockSecOpsClient, adapter: SecOpsManagedAdapter
) -> None:
    cat_uuid = "a5366ed8-3746-2423-a972-98535279f96a"
    rs_uuid = "1c4ab1f6-d801-d6a9-1177-3ec3dd5bcbe9"
    mock_client.set_response(
        "GET",
        "curatedRuleSetCategories",
        {
            "curatedRuleSetCategories": [
                {
                    "name": f"{INSTANCE_BASE}/curatedRuleSetCategories/{cat_uuid}",
                    "displayName": "Linux Threats",
                }
            ]
        },
    )
    mock_client.set_response(
        "GET",
        "curatedRuleSetCategories/-/curatedRuleSets",
        {
            "curatedRuleSets": [
                {
                    "name": (
                        f"{INSTANCE_BASE}/curatedRuleSetCategories/{cat_uuid}/"
                        f"curatedRuleSets/{rs_uuid}"
                    ),
                    "displayName": "Malware Signals - Suspicious Execution",
                }
            ]
        },
    )
    mock_client.set_response(
        "GET",
        "curatedRuleSetCategories/-/curatedRuleSets/-/curatedRuleSetDeployments",
        {"curatedRuleSetDeployments": []},
    )
    mock_client.set_response("GET", "findingsRefinements", {"findingsRefinements": []})

    adapter.fetch_managed_state()
    mock_client.calls.clear()

    # Pass display name with spaces in category parameter
    adapter.set_ruleset_deployment(
        ruleset_id=rs_uuid,
        deployment_type="PRECISE",
        enabled=True,
        alerting=True,
        category="Linux Threats",
    )

    assert len(mock_client.calls) == 1
    call = mock_client.calls[0]
    assert call["method"] == "PATCH"
    # Path must use the resolved category UUID, never the display name with spaces
    assert "Linux Threats" not in call["path"]
    assert " " not in call["path"]
    expected_path = (
        f"curatedRuleSetCategories/{cat_uuid}/curatedRuleSets/{rs_uuid}/"
        "curatedRuleSetDeployments/precise"
    )
    assert call["path"] == expected_path


def test_set_ruleset_deployment_resolves_display_name_via_lazy_category_fetch(
    mock_client: MockSecOpsClient, adapter: SecOpsManagedAdapter
) -> None:
    cat_uuid = "a5366ed8-3746-2423-a972-98535279f96a"
    rs_uuid = "1c4ab1f6-d801-d6a9-1177-3ec3dd5bcbe9"
    mock_client.set_response(
        "GET",
        "curatedRuleSetCategories",
        {
            "curatedRuleSetCategories": [
                {
                    "name": f"{INSTANCE_BASE}/curatedRuleSetCategories/{cat_uuid}",
                    "displayName": "Linux Threats",
                }
            ]
        },
    )

    # Without calling fetch_managed_state first, pass display name with spaces
    adapter.set_ruleset_deployment(
        ruleset_id=rs_uuid,
        deployment_type="PRECISE",
        enabled=True,
        alerting=True,
        category="Linux Threats",
    )

    # Should have lazily queried curatedRuleSetCategories, then sent PATCH
    patch_calls = [c for c in mock_client.calls if c["method"] == "PATCH"]
    assert len(patch_calls) == 1
    call = patch_calls[0]
    assert "Linux Threats" not in call["path"]
    assert " " not in call["path"]
    expected_path = (
        f"curatedRuleSetCategories/{cat_uuid}/curatedRuleSets/{rs_uuid}/"
        "curatedRuleSetDeployments/precise"
    )
    assert call["path"] == expected_path


def test_set_ruleset_deployment_with_direct_category_uuid(
    mock_client: MockSecOpsClient, adapter: SecOpsManagedAdapter
) -> None:
    cat_uuid = "a5366ed8-3746-2423-a972-98535279f96a"
    rs_uuid = "1c4ab1f6-d801-d6a9-1177-3ec3dd5bcbe9"
    adapter.set_ruleset_deployment(
        ruleset_id=rs_uuid,
        deployment_type="PRECISE",
        enabled=True,
        alerting=True,
        category=cat_uuid,
    )

    assert len(mock_client.calls) == 1
    call = mock_client.calls[0]
    assert call["method"] == "PATCH"
    expected_path = (
        f"curatedRuleSetCategories/{cat_uuid}/curatedRuleSets/{rs_uuid}/"
        "curatedRuleSetDeployments/precise"
    )
    assert call["path"] == expected_path


def test_set_ruleset_deployment_unresolvable_category_with_spaces_falls_back_to_wildcard(
    mock_client: MockSecOpsClient, adapter: SecOpsManagedAdapter
) -> None:
    rs_uuid = "1c4ab1f6-d801-d6a9-1177-3ec3dd5bcbe9"
    mock_client.set_response(
        "GET",
        "curatedRuleSetCategories",
        {"curatedRuleSetCategories": []},
    )

    adapter.set_ruleset_deployment(
        ruleset_id=rs_uuid,
        deployment_type="PRECISE",
        enabled=True,
        alerting=True,
        category="Completely Unknown Category",
    )

    patch_calls = [c for c in mock_client.calls if c["method"] == "PATCH"]
    assert len(patch_calls) == 1
    call = patch_calls[0]
    assert "Completely Unknown Category" not in call["path"]
    assert " " not in call["path"]
    expected_path = (
        f"curatedRuleSetCategories/-/curatedRuleSets/{rs_uuid}/curatedRuleSetDeployments/precise"
    )
    assert call["path"] == expected_path
