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


def test_main_lint_duplicate_id_across_engines_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rule1 = tmp_path / "rules" / "secops" / "custom" / "r1.yaml"
    rule2 = tmp_path / "rules" / "crowdstrike" / "custom" / "r2.yaml"
    rule1.parent.mkdir(parents=True)
    rule2.parent.mkdir(parents=True)

    tests_block = (
        'tests:\n  - id: "t1"\n    description: "desc"\n    expect: 1\n    events:\n'
        '      - timestamp: "2026-09-18T00:00:00Z"\n        payload:\n          k: "v"\n'
    )
    content1 = (
        'metadata:\n  id: "11111111-2222-3333-4444-555555555555"\n  name: "rule_one"\n'
        '  description: "Desc"\n  status: "production"\n'
        'logic: "events:\\n  $e\\ncondition:\\n  $e"\n'
        'deployment:\n  enabled: true\n  alerting: true\n  run_frequency: "live"\n'
        f'runbook:\n  context: "c"\n  triage: "t"\n  response: "r"\n{tests_block}'
    )
    content2 = (
        'metadata:\n  id: "11111111-2222-3333-4444-555555555555"\n  name: "rule_two"\n'
        '  description: "Desc"\n  status: "production"\n'
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

    tests_block = (
        'tests:\n  - id: "t1"\n    description: "desc"\n    expect: 1\n    events:\n'
        '      - timestamp: "2026-09-18T00:00:00Z"\n        payload:\n          k: "v"\n'
    )
    content1 = (
        'metadata:\n  id: "11111111-1111-1111-1111-111111111111"\n  name: "shared_name"\n'
        '  description: "Desc"\n  status: "production"\n'
        'logic: "events:\\n  $e\\ncondition:\\n  $e"\n'
        'deployment:\n  enabled: true\n  alerting: true\n  run_frequency: "live"\n'
        f'runbook:\n  context: "c"\n  triage: "t"\n  response: "r"\n{tests_block}'
    )
    content2 = (
        'metadata:\n  id: "22222222-2222-2222-2222-222222222222"\n  name: "shared_name"\n'
        '  description: "Desc"\n  status: "production"\n'
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

    tests_block = (
        'tests:\n  - id: "t1"\n    description: "desc"\n    expect: 1\n    events:\n'
        '      - timestamp: "2026-09-18T00:00:00Z"\n        payload:\n          k: "v"\n'
    )
    content1 = (
        'metadata:\n  id: "11111111-1111-1111-1111-111111111111"\n  name: "shared_name"\n'
        '  description: "Desc"\n  status: "production"\n'
        'logic: "events:\\n  $e\\ncondition:\\n  $e"\n'
        'deployment:\n  enabled: true\n  alerting: true\n  run_frequency: "live"\n'
        f'runbook:\n  context: "c"\n  triage: "t"\n  response: "r"\n{tests_block}'
    )
    content2 = (
        'metadata:\n  id: "22222222-2222-2222-2222-222222222222"\n  name: "shared_name"\n'
        '  description: "Desc"\n  status: "production"\n'
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
    base_schema_content = Path("schemas/base_rule.schema.json").read_text(encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "schemas").mkdir(parents=True)
    Path("schemas/base_rule.schema.json").write_text(base_schema_content, encoding="utf-8")
    exit_code = main(["new", "engine", "testengine"])
    assert exit_code == 0
    assert (tmp_path / "src" / "graft" / "engines" / "testengine").is_dir()


def test_main_secops_new_rule(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_schema_content = Path("schemas/base_rule.schema.json").read_text(encoding="utf-8")
    secops_schema_content = Path("src/graft/engines/secops/schemas/rule.schema.json").read_text(
        encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    (tmp_path / "schemas").mkdir(parents=True)
    (tmp_path / "src" / "graft" / "engines" / "secops" / "schemas").mkdir(parents=True)
    Path("schemas/base_rule.schema.json").write_text(base_schema_content, encoding="utf-8")
    Path("src/graft/engines/secops/schemas/rule.schema.json").write_text(
        secops_schema_content, encoding="utf-8"
    )
    exit_code = main(["secops", "new", "test_login_anomaly"])
    assert exit_code == 0
    rule_file = tmp_path / "rules" / "secops" / "custom" / "test_login_anomaly.yaml"
    assert rule_file.exists()


def test_main_new_rule_via_root_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_schema_content = Path("schemas/base_rule.schema.json").read_text(encoding="utf-8")
    secops_schema_content = Path("src/graft/engines/secops/schemas/rule.schema.json").read_text(
        encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    (tmp_path / "schemas").mkdir(parents=True)
    (tmp_path / "src" / "graft" / "engines" / "secops" / "schemas").mkdir(parents=True)
    Path("schemas/base_rule.schema.json").write_text(base_schema_content, encoding="utf-8")
    Path("src/graft/engines/secops/schemas/rule.schema.json").write_text(
        secops_schema_content, encoding="utf-8"
    )
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


def test_main_secops_diff_custom_target_returns_2_when_drift() -> None:
    with (
        patch("graft.cli.engines.secops.SecOpsClient"),
        patch("graft.cli.engines.secops.SecOpsDeployerAdapter") as mock_deployer_cls,
    ):
        mock_deployer = MagicMock()
        mock_deployer.list_rules.return_value = ()
        mock_deployer_cls.return_value = mock_deployer

        exit_code = main(["secops", "diff", "--all", "--target", "custom", "--env", "staging"])
        assert exit_code == 2


def test_main_secops_diff_custom_target_returns_0_when_in_sync() -> None:
    with (
        patch("graft.cli.engines.secops.SecOpsClient"),
        patch("graft.cli.engines.secops.SecOpsDeployerAdapter") as mock_deployer_cls,
    ):
        from graft.core.loader import load_rule_from_yaml

        local_rules = [
            load_rule_from_yaml(p, schema_name="secops_custom")
            for p in sorted(Path("rules/secops/custom").rglob("*.yaml"))
        ]
        mock_deployer = MagicMock()
        mock_deployer.list_rules.return_value = tuple(local_rules)
        mock_deployer_cls.return_value = mock_deployer

        exit_code = main(["secops", "diff", "--all", "--target", "custom", "--env", "staging"])
        assert exit_code == 0


def test_main_secops_apply_all_targets() -> None:
    with (
        patch("graft.cli.engines.secops.SecOpsClient"),
        patch("graft.cli.engines.secops.SecOpsDeployerAdapter") as mock_deployer_cls,
        patch("graft.cli.engines.secops.SecOpsManagedAdapter") as mock_managed_cls,
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
        patch("graft.cli.engines.secops.SecOpsClient"),
        patch("graft.cli.engines.secops.SecOpsDeployerAdapter") as mock_deployer_cls,
        patch("graft.cli.engines.secops.SecOpsManagedAdapter") as mock_managed_cls,
    ):
        mock_deployer = MagicMock()
        mock_deployer.list_rules.return_value = ()
        mock_deployer_cls.return_value = mock_deployer

        from graft.engines.secops.managed_loader import load_managed_manifest_from_yaml

        mock_managed = MagicMock()
        mock_managed.fetch_managed_state.return_value = load_managed_manifest_from_yaml(
            "rules/secops/managed.yaml"
        )
        mock_managed_cls.return_value = mock_managed

        exit_code = main(["secops", "diff", "--all", "--env", "staging"])
        assert exit_code == 2
