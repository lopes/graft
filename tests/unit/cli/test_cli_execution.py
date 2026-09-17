import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from graft.cli.main import main
from graft.core.models.managed import (
    ManagedDeployment,
    ManagedRuleSet,
    ManagedState,
)


def test_main_no_args_shows_help(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main([])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "usage:" in captured.out or "usage:" in captured.err


def test_main_lint_clean(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["lint", "rules/secops/custom/gcp_iam_service_account_key_create.yaml"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "PASS" in captured.out or "clean" in captured.out.lower()


def test_main_lint_json_output(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(
        ["--json", "lint", "rules/secops/custom/gcp_iam_service_account_key_create.yaml"]
    )
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["success"] is True
    assert len(data["results"]) >= 1


def test_main_lint_error(tmp_path: Path) -> None:
    bad_rule = tmp_path / "bad_rule.yaml"
    bad_rule.write_text("invalid: [yaml", encoding="utf-8")
    exit_code = main(["lint", str(bad_rule)])
    assert exit_code == 1


def test_main_new_engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_schema_content = Path("schemas/base_rule.schema.json").read_text(encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "schemas").mkdir(parents=True)
    Path("schemas/base_rule.schema.json").write_text(base_schema_content, encoding="utf-8")
    exit_code = main(["new", "engine", "testengine"])
    assert exit_code == 0
    assert (tmp_path / "src" / "graft" / "engines" / "testengine").is_dir()


def test_main_secops_new_rule(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_schema_content = Path("schemas/base_rule.schema.json").read_text(encoding="utf-8")
    secops_schema_content = Path("schemas/secops_custom.schema.json").read_text(encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "schemas").mkdir(parents=True)
    Path("schemas/base_rule.schema.json").write_text(base_schema_content, encoding="utf-8")
    Path("schemas/secops_custom.schema.json").write_text(secops_schema_content, encoding="utf-8")
    exit_code = main(["secops", "new", "test_login_anomaly"])
    assert exit_code == 0
    rule_file = tmp_path / "rules" / "secops" / "custom" / "test_login_anomaly.yaml"
    assert rule_file.exists()


def test_main_new_rule_via_root_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_schema_content = Path("schemas/base_rule.schema.json").read_text(encoding="utf-8")
    secops_schema_content = Path("schemas/secops_custom.schema.json").read_text(encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "schemas").mkdir(parents=True)
    Path("schemas/base_rule.schema.json").write_text(base_schema_content, encoding="utf-8")
    Path("schemas/secops_custom.schema.json").write_text(secops_schema_content, encoding="utf-8")
    exit_code = main(["new", "rule", "test_root_new_rule", "--engine", "secops"])
    assert exit_code == 0
    rule_file = tmp_path / "rules" / "secops" / "custom" / "test_root_new_rule.yaml"
    assert rule_file.exists()


def test_main_update_mitre(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["update-mitre"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "MITRE" in captured.out


def test_main_export(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["export", "metadata", "--format", "json"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert len(data) >= 1


def test_main_secops_managed_diff_returns_2_on_drift() -> None:
    with (
        patch("graft.cli.engines.secops.SecOpsClient"),
        patch("graft.cli.engines.secops.SecOpsManagedAdapter") as mock_adapter_cls,
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
        patch("graft.cli.engines.secops.SecOpsClient"),
        patch("graft.cli.engines.secops.SecOpsManagedAdapter") as mock_adapter_cls,
    ):
        from graft.engines.secops.managed_loader import load_managed_manifest_from_yaml

        live_state = load_managed_manifest_from_yaml("rules/secops/managed.yaml")
        mock_adapter = MagicMock()
        mock_adapter.fetch_managed_state.return_value = live_state
        mock_adapter_cls.return_value = mock_adapter

        exit_code = main(["secops", "managed", "diff", "--env", "staging"])
        assert exit_code == 0
