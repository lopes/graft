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
    exit_code = main(["lint", "rulesets/secops/custom/gcp_iam_service_account_key_create.yaml"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "PASS" in captured.out or "clean" in captured.out.lower()


def test_main_lint_json_output(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(
        ["--json", "lint", "rulesets/secops/custom/gcp_iam_service_account_key_create.yaml"]
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


def test_main_lint_duplicate_id_across_engines_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rule1 = tmp_path / "rulesets" / "secops" / "custom" / "r1.yaml"
    rule2 = tmp_path / "rulesets" / "crowdstrike" / "custom" / "r2.yaml"
    rule1.parent.mkdir(parents=True)
    rule2.parent.mkdir(parents=True)

    meta_extra = (
        '  owners: ["SOC"]\n'
        '  mitre:\n    execution: ["T1059"]\n'
        '  tags: ["test"]\n'
        '  references: ["ref"]\n'
    )
    tests_block = (
        'tests:\n  - id: "t1"\n    description: "desc"\n    expect: 1\n    events:\n'
        '      - timestamp: "2026-09-18T00:00:00Z"\n        payload:\n          k: "v"\n'
    )
    content1 = (
        'metadata:\n  id: "11111111-2222-3333-4444-555555555555"\n  name: "rule_one"\n'
        f'  description: "Desc"\n{meta_extra}'
        'logic: "events:\\n  $e\\ncondition:\\n  $e"\n'
        'deployment:\n  enabled: true\n  alerting: true\n  run_frequency: "live"\n'
        f'runbook:\n  context: "c"\n  triage: "t"\n  response: "r"\n{tests_block}'
    )
    content2 = (
        'metadata:\n  id: "11111111-2222-3333-4444-555555555555"\n  name: "rule_two"\n'
        f'  description: "Desc"\n{meta_extra}'
        'logic: "events:\\n  $e\\ncondition:\\n  $e"\n'
        'deployment:\n  enabled: true\n  alerting: true\n  run_frequency: "live"\n'
        f'runbook:\n  context: "c"\n  triage: "t"\n  response: "r"\n{tests_block}'
    )
    rule1.write_text(content1, encoding="utf-8")
    rule2.write_text(content2, encoding="utf-8")

    exit_code = main(["lint", str(rule1), str(rule2)])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Duplicate rule metadata.id" in captured.err


def test_main_lint_duplicate_name_in_same_engine_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rule1 = tmp_path / "rules" / "secops" / "custom" / "r1.yaml"
    rule2 = tmp_path / "rules" / "secops" / "custom" / "r2.yaml"
    rule1.parent.mkdir(parents=True)

    meta_extra = (
        '  owners: ["SOC"]\n'
        '  mitre:\n    execution: ["T1059"]\n'
        '  tags: ["test"]\n'
        '  references: ["ref"]\n'
    )
    tests_block = (
        'tests:\n  - id: "t1"\n    description: "desc"\n    expect: 1\n    events:\n'
        '      - timestamp: "2026-09-18T00:00:00Z"\n        payload:\n          k: "v"\n'
    )
    content1 = (
        'metadata:\n  id: "11111111-1111-1111-1111-111111111111"\n  name: "shared_name"\n'
        f'  description: "Desc"\n{meta_extra}'
        'logic: "events:\\n  $e\\ncondition:\\n  $e"\n'
        'deployment:\n  enabled: true\n  alerting: true\n  run_frequency: "live"\n'
        f'runbook:\n  context: "c"\n  triage: "t"\n  response: "r"\n{tests_block}'
    )
    content2 = (
        'metadata:\n  id: "22222222-2222-2222-2222-222222222222"\n  name: "shared_name"\n'
        f'  description: "Desc"\n{meta_extra}'
        'logic: "events:\\n  $e\\ncondition:\\n  $e"\n'
        'deployment:\n  enabled: true\n  alerting: true\n  run_frequency: "live"\n'
        f'runbook:\n  context: "c"\n  triage: "t"\n  response: "r"\n{tests_block}'
    )
    rule1.write_text(content1, encoding="utf-8")
    rule2.write_text(content2, encoding="utf-8")

    exit_code = main(["lint", str(rule1), str(rule2)])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Duplicate rule metadata.name" in captured.err


def test_main_lint_same_name_across_different_engines_passes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rule1 = tmp_path / "rules" / "secops" / "custom" / "r1.yaml"
    rule2 = tmp_path / "rules" / "crowdstrike" / "custom" / "r2.yaml"
    rule1.parent.mkdir(parents=True)
    rule2.parent.mkdir(parents=True)

    meta_extra = (
        '  owners: ["SOC"]\n'
        '  mitre:\n    execution: ["T1059"]\n'
        '  tags: ["test"]\n'
        '  references: ["ref"]\n'
    )
    tests_block = (
        'tests:\n  - id: "t1"\n    description: "desc"\n    expect: 1\n    events:\n'
        '      - timestamp: "2026-09-18T00:00:00Z"\n        payload:\n          k: "v"\n'
    )
    content1 = (
        'metadata:\n  id: "11111111-1111-1111-1111-111111111111"\n  name: "shared_name"\n'
        f'  description: "Desc"\n{meta_extra}'
        'logic: "events:\\n  $e\\ncondition:\\n  $e"\n'
        'deployment:\n  enabled: true\n  alerting: true\n  run_frequency: "live"\n'
        f'runbook:\n  context: "c"\n  triage: "t"\n  response: "r"\n{tests_block}'
    )
    content2 = (
        'metadata:\n  id: "22222222-2222-2222-2222-222222222222"\n  name: "shared_name"\n'
        f'  description: "Desc"\n{meta_extra}'
        'logic: "events:\\n  $e\\ncondition:\\n  $e"\n'
        'deployment:\n  enabled: true\n  alerting: true\n  run_frequency: "live"\n'
        f'runbook:\n  context: "c"\n  triage: "t"\n  response: "r"\n{tests_block}'
    )
    rule1.write_text(content1, encoding="utf-8")
    rule2.write_text(content2, encoding="utf-8")

    exit_code = main(["lint", str(rule1), str(rule2)])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Lint complete: 2 passed" in captured.out


def test_main_new_engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_schema_content = Path("src/graft/core/schemas/base_custom.schema.json").read_text(
        encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src" / "graft" / "core" / "schemas").mkdir(parents=True)
    (tmp_path / "src" / "graft" / "core" / "schemas" / "base_custom.schema.json").write_text(
        base_schema_content, encoding="utf-8"
    )
    exit_code = main(["new", "engine", "testengine"])
    assert exit_code == 0
    engine_dir = tmp_path / "src" / "graft" / "engines" / "testengine"
    assert engine_dir.is_dir()
    assert (engine_dir / "engine.yaml").is_file()
    assert (engine_dir / "adapter.py").is_file()


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
    Path("src/graft/engines/secops/schemas/custom.schema.json").write_text(
        secops_schema_content, encoding="utf-8"
    )
    exit_code = main(["secops", "new", "test_login_anomaly"])
    assert exit_code == 0
    rule_file = tmp_path / "rulesets" / "secops" / "custom" / "test_login_anomaly.yaml"
    assert rule_file.exists()


def test_main_new_rule_via_root_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
    Path("src/graft/engines/secops/schemas/custom.schema.json").write_text(
        secops_schema_content, encoding="utf-8"
    )
    exit_code = main(["new", "rule", "test_root_new_rule", "--engine", "secops"])
    assert exit_code == 0
    rule_file = tmp_path / "rulesets" / "secops" / "custom" / "test_root_new_rule.yaml"
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
        from graft.engines.secops.managed_loader import load_managed_manifest_from_yaml

        live_state = load_managed_manifest_from_yaml("rulesets/secops/managed.yaml")
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
        from graft.core.loader import load_rule_from_yaml

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

        from graft.engines.secops.managed_loader import load_managed_manifest_from_yaml

        mock_managed = MagicMock()
        mock_managed.fetch_managed_state.return_value = load_managed_manifest_from_yaml(
            "rulesets/secops/managed.yaml"
        )
        mock_managed_cls.return_value = mock_managed

        exit_code = main(["secops", "diff", "--all", "--env", "staging"])
        assert exit_code == 2


def test_main_new_rule_execution(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    custom_target = tmp_path / "custom_out.yaml"
    exit_code = main(
        ["new", "rule", "my_new_rule", "--engine", "secops", "--out", str(custom_target)]
    )
    assert exit_code == 0
    assert custom_target.exists()
    captured = capsys.readouterr()
    assert "Scaffolded rule template at:" in captured.out


def test_main_new_rule_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    custom_target = tmp_path / "custom_out.yaml"
    exit_code = main(
        ["--json", "new", "rule", "json_rule", "--engine", "secops", "--out", str(custom_target)]
    )
    assert exit_code == 0
    assert custom_target.exists()
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["success"] is True
    assert data["path"] == str(custom_target)


def test_main_lint_ignores_archived_and_underscore_folders(tmp_path: Path) -> None:
    rulesets_dir = tmp_path / "rulesets"
    archived_dir = rulesets_dir / "secops" / "_archived"
    custom_dir = rulesets_dir / "secops" / "custom"
    archived_dir.mkdir(parents=True)
    custom_dir.mkdir(parents=True)

    # Valid rule in custom
    valid_rule = custom_dir / "valid.yaml"
    valid_rule.write_text(
        'metadata:\n  id: "11111111-2222-3333-4444-555555555555"\n  name: "valid_rule"\n'
        '  description: "Valid rule description"\n  owners: ["alice"]\n'
        '  mitre:\n    execution:\n      - "T1059"\n'
        '  tags: ["test"]\n  references: ["Internal reference"]\n'
        'logic: |\n  events:\n    $e.metadata.event_type = "USER_LOGIN"\n  condition:\n    $e\n'
        'deployment:\n  run_frequency: "live"\n'
        "  enabled: true\n  alerting: true\n"
        'runbook:\n  context: "Investigation context"\n'
        '  triage: "Triage instructions"\n  response: "Response instructions"\n'
        'tests:\n  - id: "t1"\n    description: "test"\n    expect: 1\n    events:\n'
        '      - timestamp: "2026-09-18T00:00:00Z"\n        payload:\n          k: "v"\n',
        encoding="utf-8",
    )

    # Corrupted / invalid rule placed in _archived
    corrupted_archived = archived_dir / "broken_archived.yaml"
    corrupted_archived.write_text("invalid: [broken yaml content", encoding="utf-8")

    # Lint scanning the root directory should ignore _archived and return 0
    exit_code = main(["lint", "--rules-dir", str(rulesets_dir)])
    assert exit_code == 0


def test_main_update_mitre_success(capsys: pytest.CaptureFixture[str]) -> None:
    with patch(
        "graft.cli.commands_core.update_mitre_taxonomy",
        return_value={"version": "19.2", "techniques": {"T1059": {}}, "tactics": {"execution": {}}},
    ):
        exit_code = main(["update-mitre"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Updated MITRE ATT&CK Enterprise taxonomy to v19.2" in captured.out


def test_main_update_mitre_json_output(capsys: pytest.CaptureFixture[str]) -> None:
    with patch(
        "graft.cli.commands_core.update_mitre_taxonomy",
        return_value={"version": "19.2", "techniques": {"T1059": {}}, "tactics": {"execution": {}}},
    ):
        exit_code = main(["--json", "update-mitre"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["success"] is True
    assert data["version"] == "19.2"


def test_main_configures_utc_iso8601_log_formatter() -> None:
    import logging
    import time

    with patch("graft.cli.main.logging.basicConfig") as mock_basic_config:
        exit_code = main(["lint", "rulesets/secops/custom/gcp_iam_service_account_key_create.yaml"])
    assert exit_code == 0
    assert logging.Formatter.converter is time.gmtime
    mock_basic_config.assert_called_once_with(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )


def test_main_apply_failure_logs_rule_context_and_skips_managed(
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import logging

    from graft.engines.secops.client import SecOpsApiError

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


def test_main_uncaught_exception_logged_via_logger_error(
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import logging

    with (
        patch(
            "graft.cli.main.execute_lint",
            side_effect=RuntimeError("unhandled failure during command"),
        ),
        caplog.at_level(logging.ERROR, logger="graft.cli"),
    ):
        exit_code = main(["lint"])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Unexpected error:" not in captured.err
    assert any("unhandled failure during command" in r.message for r in caplog.records)
