import json
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from graft.cli.main import build_parser, main
from graft.core.loader import load_rule_from_yaml
from graft.core.models.managed import (
    ManagedDeployment,
    ManagedRuleSet,
    ManagedState,
)
from graft.core.ports.replay import ReplayResult
from graft.engines.secops.client import SecOpsApiError
from graft.engines.secops.managed_loader import load_managed_manifest_from_yaml


def test_parse_secops_subcommands() -> None:
    parser = build_parser()

    args = parser.parse_args(["secops", "new", "test_rule"])
    assert args.command == "secops"
    assert args.engine_command == "new"
    assert args.rule_name == "test_rule"
    assert args.managed is None

    args_managed = parser.parse_args(["secops", "new", "managed_rule", "--managed", "rs-123"])
    assert args_managed.managed == "rs-123"

    args = parser.parse_args(["secops", "verify", "--env", "staging"])
    assert args.command == "secops"
    assert args.engine_command == "verify"
    assert args.env == "staging"

    args = parser.parse_args(["secops", "test", "--require-staging", "--changed-only"])
    assert args.command == "secops"
    assert args.engine_command == "test"
    assert args.require_staging is True
    assert args.changed_only is True

    args = parser.parse_args(["secops", "diff", "--env", "production", "--target", "managed"])
    assert args.command == "secops"
    assert args.engine_command == "diff"
    assert args.env == "production"
    assert args.target == "managed"

    args = parser.parse_args(["secops", "apply", "--env", "staging"])
    assert args.command == "secops"
    assert args.engine_command == "apply"

    args = parser.parse_args(["secops", "managed", "pull", "--env", "production"])
    assert args.command == "secops"
    assert args.engine_command == "managed"
    assert args.managed_command == "pull"
    assert args.env == "production"


def test_main_secops_lint_clean(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["lint", "rulesets/secops/custom/gcp_service_account_key_created.yaml"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "PASS" in captured.out or "clean" in captured.out.lower()


def test_main_secops_new_rule(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_schema_content = Path("src/graft/core/schemas/base_custom.schema.json").read_text(
        encoding="utf-8"
    )
    secops_schema_content = Path("src/graft/engines/secops/schemas/custom.schema.json").read_text(
        encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src" / "graft" / "core" / "schemas").mkdir(parents=True)
    (tmp_path / "src" / "graft" / "engines" / "secops" / "schemas").mkdir(parents=True)
    (tmp_path / "src" / "graft" / "core" / "schemas" / "base_custom.schema.json").write_text(
        base_schema_content, encoding="utf-8"
    )
    (
        tmp_path / "src" / "graft" / "engines" / "secops" / "schemas" / "custom.schema.json"
    ).write_text(secops_schema_content, encoding="utf-8")
    exit_code = main(["secops", "new", "test_login_anomaly"])
    assert exit_code == 0
    rule_file = tmp_path / "rulesets" / "secops" / "custom" / "test_login_anomaly.yaml"
    assert rule_file.exists()


def test_main_secops_new_managed_rule(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_managed_content = Path("src/graft/core/schemas/base_managed.schema.json").read_text(
        encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src" / "graft" / "core" / "schemas").mkdir(parents=True)
    (tmp_path / "src" / "graft" / "core" / "schemas" / "base_managed.schema.json").write_text(
        base_managed_content, encoding="utf-8"
    )
    exit_code = main(
        [
            "secops",
            "new",
            "gcti_active_breach_host_indicators",
            "--managed",
            "f5533b66-9327-9880-93e6-75a738ac2345",
        ]
    )
    assert exit_code == 0
    rule_file = (
        tmp_path / "rulesets" / "secops" / "managed" / "gcti_active_breach_host_indicators.yaml"
    )
    assert rule_file.exists()


def test_main_secops_managed_diff_returns_2_on_drift() -> None:
    with (
        patch("graft.engines.secops.adapter.SecOpsClient"),
        patch("graft.engines.secops.adapter.SecOpsManagedAdapter") as mock_adapter_cls,
    ):
        mock_adapter = MagicMock()
        mock_adapter.fetch_managed_state.return_value = ManagedState(
            rulesets=(
                ManagedRuleSet(
                    id="rs-cloud-threats",
                    name="Cloud Threat Detections",
                    category="CLOUD",
                    deployments=(
                        ManagedDeployment(type="PRECISE", enabled=False, alerting=False),
                        ManagedDeployment(type="BROAD", enabled=False, alerting=False),
                    ),
                ),
            ),
            exclusions=(),
        )
        mock_adapter_cls.return_value = mock_adapter

        exit_code = main(["secops", "managed", "diff", "--env", "staging"])
        assert exit_code == 2


def test_main_secops_managed_diff_returns_0_when_in_sync() -> None:
    with (
        patch("graft.engines.secops.adapter.SecOpsClient"),
        patch("graft.engines.secops.adapter.SecOpsManagedAdapter") as mock_adapter_cls,
    ):
        live_state = load_managed_manifest_from_yaml("rulesets/secops/managed/index.yaml")
        mock_adapter = MagicMock()
        mock_adapter.fetch_managed_state.return_value = live_state
        mock_adapter_cls.return_value = mock_adapter

        exit_code = main(["secops", "managed", "diff", "--env", "staging"])
        assert exit_code == 0


def test_main_secops_diff_custom_target_returns_2_when_drift() -> None:
    with (
        patch("graft.engines.secops.adapter.SecOpsClient"),
        patch("graft.engines.secops.adapter.SecOpsDeployerAdapter") as mock_deployer_cls,
    ):
        mock_deployer = MagicMock()
        mock_deployer.list_rules.return_value = ()
        mock_deployer_cls.return_value = mock_deployer

        exit_code = main(["secops", "diff", "--all", "--target", "custom", "--env", "staging"])
        assert exit_code == 2


def test_main_secops_diff_custom_target_returns_0_when_in_sync() -> None:
    with (
        patch("graft.engines.secops.adapter.SecOpsClient"),
        patch("graft.engines.secops.adapter.SecOpsDeployerAdapter") as mock_deployer_cls,
    ):
        local_rules = [
            load_rule_from_yaml(p, schema_name="secops_custom")
            for p in sorted(Path("rulesets/secops/custom").rglob("*.yaml"))
        ]
        mock_deployer = MagicMock()
        mock_deployer.list_rules.return_value = tuple(local_rules)
        mock_deployer_cls.return_value = mock_deployer

        exit_code = main(["secops", "diff", "--all", "--target", "custom", "--env", "staging"])
        assert exit_code == 0


def test_main_secops_apply_all_targets() -> None:
    with (
        patch("graft.engines.secops.adapter.SecOpsClient"),
        patch("graft.engines.secops.adapter.SecOpsDeployerAdapter") as mock_deployer_cls,
        patch("graft.engines.secops.adapter.SecOpsManagedAdapter") as mock_managed_cls,
    ):
        mock_deployer = MagicMock()
        mock_deployer.list_rules.return_value = ()
        mock_deployer_cls.return_value = mock_deployer

        mock_managed = MagicMock()
        mock_managed.fetch_managed_state.return_value = ManagedState(rulesets=())
        mock_managed_cls.return_value = mock_managed

        exit_code = main(["secops", "apply", "--all", "--env", "staging"])
        assert exit_code == 0
        assert mock_deployer.create_rule.call_count > 0
        assert mock_managed.fetch_managed_state.call_count == 1


def test_main_secops_diff_all_targets_drift() -> None:
    with (
        patch("graft.engines.secops.adapter.SecOpsClient"),
        patch("graft.engines.secops.adapter.SecOpsDeployerAdapter") as mock_deployer_cls,
        patch("graft.engines.secops.adapter.SecOpsManagedAdapter") as mock_managed_cls,
    ):
        mock_deployer = MagicMock()
        mock_deployer.list_rules.return_value = ()
        mock_deployer_cls.return_value = mock_deployer

        mock_managed = MagicMock()
        mock_managed.fetch_managed_state.return_value = load_managed_manifest_from_yaml(
            "rulesets/secops/managed/index.yaml"
        )
        mock_managed_cls.return_value = mock_managed

        exit_code = main(["secops", "diff", "--all", "--env", "staging"])
        assert exit_code == 2


def test_main_secops_apply_failure_logs_rule_context_and_skips_managed(
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with (
        patch("graft.engines.secops.adapter.SecOpsClient"),
        patch("graft.engines.secops.adapter.SecOpsDeployerAdapter") as mock_deployer_cls,
        patch("graft.engines.secops.adapter.SecOpsManagedAdapter") as mock_managed_cls,
    ):
        mock_deployer = MagicMock()
        mock_deployer.list_rules.return_value = ()
        mock_deployer.create_rule.side_effect = SecOpsApiError(
            "Invalid syntax",
            400,
            status="INVALID_ARGUMENT",
            method="POST",
            path="rules",
        )
        mock_deployer_cls.return_value = mock_deployer

        mock_managed = MagicMock()
        mock_managed_cls.return_value = mock_managed

        with caplog.at_level(logging.INFO):
            exit_code = main(["secops", "apply", "--all", "--env", "staging"])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Unexpected error:" not in captured.err
    messages = [r.message for r in caplog.records]
    assert any(
        "Failed creating custom rule" in m
        and "SecOps API Error 400 (INVALID_ARGUMENT) on POST rules: Invalid syntax" in m
        for m in messages
    )
    assert any("Custom rules reconciliation aborted:" in m for m in messages)
    assert any(
        "Skipping managed state reconciliation due to custom rules failure" in m for m in messages
    )


def test_main_secops_verify_explicit_managed_rule_or_index_skips_cleanly(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(
        [
            "--json",
            "secops",
            "verify",
            "rulesets/secops/managed/gcti_breach_network_indicator_matched.yaml",
            "rulesets/secops/managed/index.yaml",
        ]
    )
    assert exit_code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["success"] is True
    assert data["total"] == 0


def test_secops_cli_test_graceful_degradation_when_staging_missing(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    for var in (
        "GRAFT_SECOPS_STAGING_PROJECT",
        "GRAFT_SECOPS_PROJECT",
        "GRAFT_SECOPS_PROD_PROJECT",
        "GRAFT_STAGING_PROJECT",
        "GRAFT_PROJECT",
        "GRAFT_PROD_PROJECT",
    ):
        monkeypatch.delenv(var, raising=False)

    exit_code = main(
        ["secops", "test", "rulesets/secops/custom/gcp_service_account_key_created.yaml"]
    )
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "WARNING" in captured.out or "Skipping" in captured.out


def test_secops_cli_test_skips_when_pointing_to_prod_tenant(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("GRAFT_SECOPS_STAGING_PROJECT", raising=False)
    monkeypatch.delenv("GRAFT_STAGING_PROJECT", raising=False)
    monkeypatch.setenv("GRAFT_SECOPS_PROD_PROJECT", "prod-proj")
    monkeypatch.setenv("GRAFT_SECOPS_PROD_LOCATION", "us")
    monkeypatch.setenv("GRAFT_SECOPS_PROD_INSTANCE_ID", "prod-inst")

    exit_code = main(
        ["secops", "test", "rulesets/secops/custom/gcp_service_account_key_created.yaml"]
    )
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "WARNING" in captured.out
    assert "cannot run against production" in captured.out


def test_secops_cli_test_fails_when_pointing_to_prod_tenant_and_require_staging(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("GRAFT_SECOPS_STAGING_PROJECT", raising=False)
    monkeypatch.delenv("GRAFT_STAGING_PROJECT", raising=False)
    monkeypatch.setenv("GRAFT_SECOPS_PROD_PROJECT", "prod-proj")
    monkeypatch.setenv("GRAFT_SECOPS_PROD_LOCATION", "us")
    monkeypatch.setenv("GRAFT_SECOPS_PROD_INSTANCE_ID", "prod-inst")

    exit_code = main(
        [
            "secops",
            "test",
            "rulesets/secops/custom/gcp_service_account_key_created.yaml",
            "--require-staging",
        ]
    )
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Error" in captured.err


def test_secops_cli_test_execution_passed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("GRAFT_SECOPS_STAGING_PROJECT", "test-proj")
    monkeypatch.setenv("GRAFT_SECOPS_STAGING_LOCATION", "us")
    monkeypatch.setenv("GRAFT_SECOPS_STAGING_INSTANCE_ID", "test-inst")

    with patch("graft.engines.secops.adapter.SecOpsReplayAdapter") as mock_adapter_cls:
        mock_adapter = MagicMock()
        mock_adapter.run_test_vector.return_value = ReplayResult(
            test_id="test_powershell_download_cradle",
            passed=True,
            message="Passed: 1 detection matched",
            matched_events_count=1,
        )
        mock_adapter_cls.return_value = mock_adapter

        exit_code = main(
            ["secops", "test", "rulesets/secops/custom/gcp_service_account_key_created.yaml"]
        )
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "PASS" in captured.out


def test_secops_export_catalog_and_matrix_from_live_rulesets(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(["export", "matrix", "--engine", "secops", "--color", "#2e7d32"])
    assert exit_code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["name"] == "Graft Detection Coverage (secops)"
    assert any(
        m["name"] == "engine" and "secops" in m["value"] for m in data["techniques"][0]["metadata"]
    )

    exit_code_cat = main(["export", "catalog", "--format", "json"])
    assert exit_code_cat == 0
    cat_data = json.loads(capsys.readouterr().out)
    rule_names = [r["name"] for r in cat_data]
    assert "workspace_nrd_email_opened" in rule_names
    assert "gcti_breach_network_indicator_matched" in rule_names
