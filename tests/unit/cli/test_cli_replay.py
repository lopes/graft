import argparse
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from graft.cli.engine_controller import EngineCommandController
from graft.core.engine_registry import EngineRegistry
from graft.core.models.engine import EngineCapabilities, EngineManifest
from graft.core.ports.replay import ReplayResult


def _make_manifest() -> EngineManifest:
    return EngineManifest(
        name="siem_alpha",
        display_name="SIEM Alpha",
        description="SIEM Alpha Engine",
        adapter_class="graft.engines.siem_alpha.adapter:SiemAlphaAdapter",
        capabilities=EngineCapabilities(
            custom_rules=True,
            datasets=True,
            syntax_verification=True,
            managed_rules=True,
            replay_testing=True,
        ),
    )


def _write_rule_with_test(tmp_path: Path) -> Path:
    rule_path = (
        tmp_path / "rulesets" / "siem_alpha" / "custom" / "gcp_service_account_key_created.yaml"
    )
    rule_path.parent.mkdir(parents=True, exist_ok=True)
    rule_path.write_text(
        """metadata:
  id: "11111111-2222-3333-4444-555555555555"
  name: "gcp_service_account_key_created"
  description: "Detects service account key creation."
  owners:
    - "SOC"
  mitre:
    persistence:
      - "T1098.001"
  tags:
    - "iam"
  references:
    - "https://attack.mitre.org/techniques/T1098/001/"
logic: "event_type == 'CREATE_SERVICE_ACCOUNT_KEY'"
deployment:
  enabled: true
  alerting: true
  run_frequency: "live"
runbook:
  context: "Context"
  triage: "Triage"
  response: "Response"
tests:
  - id: "test_powershell_download_cradle"
    description: "Positive match"
    expect: 1
    events:
      - timestamp: "2026-09-18T00:00:00Z"
        payload:
          event_type: "CREATE_SERVICE_ACCOUNT_KEY"
""",
        encoding="utf-8",
    )
    return rule_path


def test_cli_test_graceful_degradation_when_staging_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rule_path = _write_rule_with_test(tmp_path)
    mock_adapter = MagicMock()
    mock_adapter.get_replay.return_value = None

    reg = EngineRegistry()
    monkeypatch.setattr(reg, "load_adapter", lambda name, env="staging": mock_adapter)
    controller = EngineCommandController(_make_manifest(), reg)
    args = argparse.Namespace(
        engine_command="test",
        paths=[str(rule_path)],
        require_staging=False,
        changed_only=False,
    )
    exit_code = controller.execute(args, json_output=False)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "WARNING" in captured.out or "Skipping" in captured.out


def test_cli_test_require_staging_fails_when_staging_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rule_path = _write_rule_with_test(tmp_path)
    mock_adapter = MagicMock()
    mock_adapter.get_replay.return_value = None

    reg = EngineRegistry()
    monkeypatch.setattr(reg, "load_adapter", lambda name, env="staging": mock_adapter)
    controller = EngineCommandController(_make_manifest(), reg)
    args = argparse.Namespace(
        engine_command="test",
        paths=[str(rule_path)],
        require_staging=True,
        changed_only=False,
    )
    exit_code = controller.execute(args, json_output=False)
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Error" in captured.err or "require-staging" in captured.err


def test_cli_test_execution_all_passed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rule_path = _write_rule_with_test(tmp_path)
    mock_replay = MagicMock()
    mock_replay.run_test_vector.return_value = ReplayResult(
        test_id="test_powershell_download_cradle",
        passed=True,
        message="Passed: 1 detection matched",
        matched_events_count=1,
    )
    mock_adapter = MagicMock()
    mock_adapter.get_replay.return_value = mock_replay

    reg = EngineRegistry()
    monkeypatch.setattr(reg, "load_adapter", lambda name, env="staging": mock_adapter)
    controller = EngineCommandController(_make_manifest(), reg)
    args = argparse.Namespace(
        engine_command="test",
        paths=[str(rule_path)],
        require_staging=False,
        changed_only=False,
    )
    exit_code = controller.execute(args, json_output=False)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "PASS" in captured.out


def test_cli_test_execution_assertion_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rule_path = _write_rule_with_test(tmp_path)
    mock_replay = MagicMock()
    mock_replay.run_test_vector.return_value = ReplayResult(
        test_id="test_powershell_download_cradle",
        passed=False,
        message="Failed: expected 1, got 0",
        matched_events_count=0,
    )
    mock_adapter = MagicMock()
    mock_adapter.get_replay.return_value = mock_replay

    reg = EngineRegistry()
    monkeypatch.setattr(reg, "load_adapter", lambda name, env="staging": mock_adapter)
    controller = EngineCommandController(_make_manifest(), reg)
    args = argparse.Namespace(
        engine_command="test",
        paths=[str(rule_path)],
        require_staging=False,
        changed_only=False,
    )
    exit_code = controller.execute(args, json_output=False)
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "FAIL" in captured.err or "FAIL" in captured.out


def test_cli_test_json_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rule_path = _write_rule_with_test(tmp_path)
    mock_replay = MagicMock()
    mock_replay.run_test_vector.return_value = ReplayResult(
        test_id="test_powershell_download_cradle",
        passed=True,
        message="Passed",
        matched_events_count=1,
    )
    mock_adapter = MagicMock()
    mock_adapter.get_replay.return_value = mock_replay

    reg = EngineRegistry()
    monkeypatch.setattr(reg, "load_adapter", lambda name, env="staging": mock_adapter)
    controller = EngineCommandController(_make_manifest(), reg)
    args = argparse.Namespace(
        engine_command="test",
        paths=[str(rule_path)],
        require_staging=False,
        changed_only=False,
    )
    exit_code = controller.execute(args, json_output=True)
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["success"] is True
    assert len(data["results"]) >= 1


def test_cli_test_skips_when_pointing_to_prod_tenant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rule_path = _write_rule_with_test(tmp_path)
    mock_adapter = MagicMock()
    mock_adapter.get_replay.side_effect = RuntimeError(
        "Replay tests cannot run against production tenant."
    )

    reg = EngineRegistry()
    monkeypatch.setattr(reg, "load_adapter", lambda name, env="staging": mock_adapter)
    controller = EngineCommandController(_make_manifest(), reg)
    args = argparse.Namespace(
        engine_command="test",
        paths=[str(rule_path)],
        require_staging=False,
        changed_only=False,
    )
    exit_code = controller.execute(args, json_output=False)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "WARNING" in captured.out
    assert "cannot run against production" in captured.out


def test_cli_test_fails_when_pointing_to_prod_tenant_and_require_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rule_path = _write_rule_with_test(tmp_path)
    mock_adapter = MagicMock()
    mock_adapter.get_replay.side_effect = RuntimeError(
        "Replay tests cannot run against production tenant."
    )

    reg = EngineRegistry()
    monkeypatch.setattr(reg, "load_adapter", lambda name, env="staging": mock_adapter)
    controller = EngineCommandController(_make_manifest(), reg)
    args = argparse.Namespace(
        engine_command="test",
        paths=[str(rule_path)],
        require_staging=True,
        changed_only=False,
    )
    exit_code = controller.execute(args, json_output=False)
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Error" in captured.err
