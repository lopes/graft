import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from graft.cli.main import main
from graft.core.loader import load_rule_from_yaml
from graft.engines.secops.client import SecOpsClient


@pytest.fixture
def mock_secops_client() -> MagicMock:
    client = MagicMock(spec=SecOpsClient)

    def fake_request(
        method: str,
        endpoint: str,
        body: object = None,
        params: object = None,
        **kwargs: object,
    ) -> dict[str, object]:
        inst_base = "projects/p/locations/us/instances/i"
        if method == "GET" and endpoint == "rules":
            return {
                "rules": [
                    {
                        "name": f"{inst_base}/rules/ru_b1d72370-5fa3-4cb8-a579-22a468d6f101",
                        "displayName": "Workspace NRD Phishing",
                        "text": """rule workspace_nrd_phishing {
  meta:
    id = "b1d72370-5fa3-4cb8-a579-22a468d6f101"
    description = "Detects phishing from newly registered domain"
    status = "production"
    author = "Detection Team"
  events:
    $e.metadata.event_type = "EMAIL_TRANSACTION"
  condition:
    $e
}""",
                    },
                    {
                        "name": f"{inst_base}/rules/ru_unnamed_legacy_99",
                        "displayName": "Legacy Ingress Alert",
                        "text": """rule legacy_ingress {
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
  condition:
    $e
}""",
                    },
                ]
            }
        if method == "GET" and endpoint == "rules/-/deployments":
            return {
                "ruleDeployments": [
                    {
                        "name": (
                            f"{inst_base}/rules/ru_b1d72370-5fa3-4cb8-a579-22a468d6f101/deployment"
                        ),
                        "enabled": True,
                        "alerting": True,
                    },
                    {
                        "name": f"{inst_base}/rules/ru_unnamed_legacy_99/deployment",
                        "enabled": False,
                        "alerting": False,
                    },
                ]
            }
        if method == "GET" and endpoint == "curatedRuleSetCategories":
            return {
                "curatedRuleSetCategories": [
                    {
                        "name": f"{inst_base}/curatedRuleSetCategories/cat_cloud",
                        "displayName": "Cloud Threats",
                    }
                ]
            }
        if method == "GET" and endpoint in (
            "curatedRuleSets",
            "curatedRuleSetCategories/-/curatedRuleSets",
        ):
            return {
                "curatedRuleSets": [
                    {
                        "name": (
                            f"{inst_base}/curatedRuleSetCategories/cat_cloud/"
                            "curatedRuleSets/ur_cloud_iam"
                        ),
                        "displayName": "Cloud IAM Abuse",
                    }
                ]
            }
        if method == "GET" and (
            endpoint == "curatedRuleSetDeployments"
            or endpoint.endswith("/curatedRuleSetDeployments")
        ):
            return {
                "curatedRuleSetDeployments": [
                    {
                        "name": (
                            f"{inst_base}/curatedRuleSetCategories/cat_cloud/"
                            "curatedRuleSets/ur_cloud_iam/curatedRuleSetDeployments/PRECISE"
                        ),
                        "enabled": True,
                        "alerting": True,
                    }
                ]
            }
        if method == "GET" and endpoint == "ruleExclusions":
            return {"ruleExclusions": []}
        return {}

    client.request.side_effect = fake_request
    return client


def test_secops_pull_custom_rules(
    mock_secops_client: MagicMock, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    custom_dir = tmp_path / "custom"

    with patch("graft.engines.secops.adapter.SecOpsClient", return_value=mock_secops_client):
        exit_code = main(
            [
                "secops",
                "pull",
                "--target",
                "custom",
                "--out-dir",
                str(custom_dir),
            ]
        )

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Pulled 2 custom rules" in out

    rule1 = custom_dir / "workspace_nrd_phishing.yaml"
    rule2 = custom_dir / "legacy_ingress.yaml"
    assert rule1.is_file()
    assert rule2.is_file()

    env1 = load_rule_from_yaml(rule1)
    assert env1.metadata.name == "workspace_nrd_phishing"
    assert env1.metadata.id == "b1d72370-5fa3-4cb8-a579-22a468d6f101"
    assert env1.deployment.enabled is True
    assert env1.deployment.alerting is True
    assert "events:" in env1.logic

    env2 = load_rule_from_yaml(rule2)
    assert env2.metadata.name == "legacy_ingress"
    assert env2.deployment.enabled is False
    assert env2.deployment.alerting is False


def test_secops_pull_managed_manifest(
    mock_secops_client: MagicMock, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest_path = tmp_path / "managed.yaml"

    with patch("graft.engines.secops.adapter.SecOpsClient", return_value=mock_secops_client):
        exit_code = main(
            [
                "secops",
                "pull",
                "--target",
                "managed",
                "--out-manifest",
                str(manifest_path),
            ]
        )

    assert exit_code == 0
    assert manifest_path.is_file()
    out = capsys.readouterr().out
    assert "Pulled managed state: 1 rulesets" in out


def test_secops_pull_all_json(
    mock_secops_client: MagicMock, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    custom_dir = tmp_path / "custom"
    manifest_path = tmp_path / "managed.yaml"

    with patch("graft.engines.secops.adapter.SecOpsClient", return_value=mock_secops_client):
        exit_code = main(
            [
                "--json",
                "secops",
                "pull",
                "--target",
                "all",
                "--out-dir",
                str(custom_dir),
                "--out-manifest",
                str(manifest_path),
            ]
        )

    assert exit_code == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["managed"]["pulled"] is True
    assert payload["managed"]["rulesets"] == 1
    assert payload["custom"]["pulled"] is True
    assert payload["custom"]["count"] == 2
    assert len(payload["custom"]["rules"]) == 2


def test_secops_pull_skip_existing_without_force(
    mock_secops_client: MagicMock, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    custom_dir = tmp_path / "custom"
    custom_dir.mkdir(parents=True, exist_ok=True)
    existing_rule = custom_dir / "workspace_nrd_phishing.yaml"
    existing_rule.write_text("existing content", encoding="utf-8")

    with patch("graft.engines.secops.adapter.SecOpsClient", return_value=mock_secops_client):
        exit_code = main(
            [
                "secops",
                "pull",
                "--target",
                "custom",
                "--out-dir",
                str(custom_dir),
            ]
        )

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Pulled 1 custom rules" in out
    assert "Skipped 1 existing files" in out
    # Existing content was NOT overwritten
    assert existing_rule.read_text(encoding="utf-8") == "existing content"

    # With --force, it should overwrite
    with patch("graft.engines.secops.adapter.SecOpsClient", return_value=mock_secops_client):
        exit_code_force = main(
            [
                "secops",
                "pull",
                "--target",
                "custom",
                "--out-dir",
                str(custom_dir),
                "--force",
            ]
        )

    assert exit_code_force == 0
    assert existing_rule.read_text(encoding="utf-8") != "existing content"
