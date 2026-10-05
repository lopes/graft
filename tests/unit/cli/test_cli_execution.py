import argparse
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from graft.cli.engine_controller import EngineCommandController
from graft.cli.main import main
from graft.core.engine_registry import EngineRegistry
from graft.core.models.engine import EngineCapabilities, EngineManifest
from graft.core.models.managed import (
    ManagedDeployment,
    ManagedRuleSet,
    ManagedState,
)


def _write_clean_rule(
    tmp_path: Path, engine: str = "siem_alpha", name: str = "sample_rule"
) -> Path:
    rule_path = tmp_path / "rulesets" / engine / "custom" / f"{name}.yaml"
    rule_path.parent.mkdir(parents=True, exist_ok=True)
    rule_path.write_text(
        f"""metadata:
  id: "11111111-2222-3333-4444-555555555555"
  name: "{name}"
  description: "Sample detection rule."
  owners:
    - "SOC"
  mitre:
    execution:
      - "T1059"
  tags:
    - "test"
  references:
    - "https://attack.mitre.org/techniques/T1059/"
logic: "event_type == 'PROCESS_LAUNCH'"
deployment:
  enabled: true
  alerting: true
  run_frequency: "live"
runbook:
  context: "Context"
  triage: "Triage"
  response: "Response"
tests: []
""",
        encoding="utf-8",
    )
    return rule_path


def test_main_no_args_shows_help(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main([])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "usage:" in captured.out or "usage:" in captured.err


def test_main_lint_clean(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rule_path = _write_clean_rule(tmp_path)
    exit_code = main(["lint", str(rule_path), "--rules-dir", str(tmp_path / "rulesets")])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "PASS" in captured.out or "clean" in captured.out.lower()


def test_main_lint_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rule_path = _write_clean_rule(tmp_path)
    exit_code = main(["--json", "lint", str(rule_path), "--rules-dir", str(tmp_path / "rulesets")])
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
    rule1 = tmp_path / "rulesets" / "siem_alpha" / "custom" / "r1.yaml"
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
    rule1 = tmp_path / "rules" / "siem_alpha" / "custom" / "r1.yaml"
    rule2 = tmp_path / "rules" / "siem_alpha" / "custom" / "r2.yaml"
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
    rule1 = tmp_path / "rules" / "siem_alpha" / "custom" / "r1.yaml"
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


def test_main_new_rule_via_root_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_schema_content = Path("src/graft/core/schemas/base_custom.schema.json").read_text(
        encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src" / "graft" / "core" / "schemas").mkdir(parents=True)
    (tmp_path / "src" / "graft" / "core" / "schemas" / "base_custom.schema.json").write_text(
        base_schema_content, encoding="utf-8"
    )
    exit_code = main(["new", "rule", "test_root_new_rule", "--engine", "sentinel"])
    assert exit_code == 0
    rule_file = tmp_path / "rulesets" / "sentinel" / "custom" / "test_root_new_rule.yaml"
    assert rule_file.exists()


def test_main_update_mitre(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["update-mitre"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "MITRE" in captured.out


def test_main_export(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write_clean_rule(tmp_path)
    exit_code = main(
        ["export", "metadata", "--format", "json", "--rules-dir", str(tmp_path / "rulesets")]
    )
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert len(data) >= 1


def test_main_new_rule_execution(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    custom_target = tmp_path / "custom_out.yaml"
    exit_code = main(
        ["new", "rule", "my_new_rule", "--engine", "sentinel", "--out", str(custom_target)]
    )
    assert exit_code == 0
    assert custom_target.exists()
    captured = capsys.readouterr()
    assert "Scaffolded rule template at:" in captured.out


def test_main_new_rule_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    custom_target = tmp_path / "custom_out.yaml"
    exit_code = main(
        ["--json", "new", "rule", "json_rule", "--engine", "sentinel", "--out", str(custom_target)]
    )
    assert exit_code == 0
    assert custom_target.exists()
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["success"] is True
    assert data["path"] == str(custom_target)


def test_main_lint_registered_managed_rule_validates_against_index_yaml(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    managed_dir = tmp_path / "rulesets" / "siem_alpha" / "managed"
    managed_dir.mkdir(parents=True)

    index_file = managed_dir / "index.yaml"
    index_file.write_text(
        """rulesets:
  - id: "f5533b66-9327-9880-93e6-75a738ac2345"
    name: "Active Breach Priority Host Indicators"
    category: "Applied Threat Intelligence"
    deployments:
      - type: "PRECISE"
        enabled: true
        alerting: false
      - type: "BROAD"
        enabled: true
        alerting: false
exclusions: []
""",
        encoding="utf-8",
    )

    rule_file = managed_dir / "gcti_host_indicators.yaml"
    rule_file.write_text(
        """metadata:
  id: "11111111-2222-3333-4444-555555555555"
  name: "gcti_host_indicators"
  description: "Registers GCTI Active Breach Host Indicators ruleset."
  owners: ["SOC"]
  mitre:
    command-and-control: ["T1071.001"]
  tags: ["siem_alpha", "managed"]
  references: ["https://example.com/docs/curated-detections"]
managed:
  id: "f5533b66-9327-9880-93e6-75a738ac2345"
runbook:
  context: "Context"
  triage: "Triage"
  response: "Response"
tests: []
""",
        encoding="utf-8",
    )

    mock_adapter = MagicMock()
    mock_adapter.load_managed_manifest.return_value = ManagedState(
        rulesets=(
            ManagedRuleSet(
                id="f5533b66-9327-9880-93e6-75a738ac2345",
                name="Active Breach Priority Host Indicators",
                category="Applied Threat Intelligence",
                deployments=(ManagedDeployment(type="PRECISE", enabled=True, alerting=False),),
            ),
        ),
        exclusions=(),
    )
    mock_adapter.has_managed_rule_id.side_effect = lambda managed_id, state: (
        managed_id == "f5533b66-9327-9880-93e6-75a738ac2345"
    )
    mock_adapter.validate_rule_dataset_references.return_value = []
    monkeypatch.setattr(
        "graft.cli.commands_core.EngineRegistry.get",
        lambda self, name: MagicMock(name=name),
    )
    monkeypatch.setattr(
        "graft.cli.commands_core.EngineRegistry.load_adapter",
        lambda self, name, env="staging": mock_adapter,
    )

    exit_code = main(["lint", str(rule_file), "--rules-dir", str(tmp_path / "rulesets")])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "1 passed, 0 failed" in captured.out


def test_main_lint_registered_managed_rule_unknown_id_in_index_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    managed_dir = tmp_path / "rulesets" / "siem_alpha" / "managed"
    managed_dir.mkdir(parents=True)

    index_file = managed_dir / "index.yaml"
    index_file.write_text("rulesets: []\nexclusions: []\n", encoding="utf-8")

    rule_file = managed_dir / "gcti_unknown.yaml"
    rule_file.write_text(
        """metadata:
  id: "11111111-2222-3333-4444-555555555555"
  name: "gcti_unknown"
  description: "References nonexistent managed ruleset ID."
  owners: ["SOC"]
  mitre:
    command-and-control: ["T1071.001"]
  tags: ["siem_alpha", "managed"]
  references: ["https://example.com/docs/curated-detections"]
managed:
  id: "nonexistent-ruleset-id-999"
runbook:
  context: "Context"
  triage: "Triage"
  response: "Response"
tests: []
""",
        encoding="utf-8",
    )

    mock_adapter = MagicMock()
    mock_adapter.load_managed_manifest.return_value = ManagedState(rulesets=(), exclusions=())
    mock_adapter.has_managed_rule_id.return_value = False
    monkeypatch.setattr(
        "graft.cli.commands_core.EngineRegistry.get",
        lambda self, name: MagicMock(name=name),
    )
    monkeypatch.setattr(
        "graft.cli.commands_core.EngineRegistry.load_adapter",
        lambda self, name, env="staging": mock_adapter,
    )

    exit_code = main(["lint", "--rules-dir", str(tmp_path / "rulesets")])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "nonexistent-ruleset-id-999" in captured.err
    assert "not found in" in captured.err


def test_main_lint_duplicate_managed_id_in_same_engine_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    managed_dir = tmp_path / "rulesets" / "siem_alpha" / "managed"
    managed_dir.mkdir(parents=True)

    index_file = managed_dir / "index.yaml"
    index_file.write_text("rulesets: []\nexclusions: []\n", encoding="utf-8")

    rule1 = managed_dir / "r1.yaml"
    rule2 = managed_dir / "r2.yaml"
    rule1.write_text(
        """metadata:
  id: "11111111-1111-1111-1111-111111111111"
  name: "managed_rule_one"
  description: "First rule linking to managed ID."
  owners: ["SOC"]
  mitre:
    command-and-control: ["T1071.001"]
  tags: ["siem_alpha", "managed"]
  references: ["ref"]
managed:
  id: "f5533b66-9327-9880-93e6-75a738ac2345"
runbook:
  context: "c"
  triage: "t"
  response: "r"
tests: []
""",
        encoding="utf-8",
    )
    rule2.write_text(
        """metadata:
  id: "22222222-2222-2222-2222-222222222222"
  name: "managed_rule_two"
  description: "Second rule linking to same managed ID."
  owners: ["SOC"]
  mitre:
    command-and-control: ["T1071.001"]
  tags: ["siem_alpha", "managed"]
  references: ["ref"]
managed:
  id: "f5533b66-9327-9880-93e6-75a738ac2345"
runbook:
  context: "c"
  triage: "t"
  response: "r"
tests: []
""",
        encoding="utf-8",
    )

    mock_adapter = MagicMock()
    mock_adapter.load_managed_manifest.return_value = ManagedState(rulesets=(), exclusions=())
    mock_adapter.has_managed_rule_id.return_value = True
    monkeypatch.setattr(
        "graft.cli.commands_core.EngineRegistry.get",
        lambda self, name: MagicMock(name=name),
    )
    monkeypatch.setattr(
        "graft.cli.commands_core.EngineRegistry.load_adapter",
        lambda self, name, env="staging": mock_adapter,
    )

    exit_code = main(["lint", "--rules-dir", str(tmp_path / "rulesets")])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Duplicate managed.id" in captured.err


def test_main_lint_ignores_archived_and_underscore_folders(tmp_path: Path) -> None:
    rulesets_dir = tmp_path / "rulesets"
    archived_dir = rulesets_dir / "siem_alpha" / "_archived"
    custom_dir = rulesets_dir / "siem_alpha" / "custom"
    archived_dir.mkdir(parents=True)
    custom_dir.mkdir(parents=True)

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

    corrupted_archived = archived_dir / "broken_archived.yaml"
    corrupted_archived.write_text("invalid: [broken yaml content", encoding="utf-8")

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


def test_main_configures_utc_iso8601_log_formatter(tmp_path: Path) -> None:
    import logging
    import time

    rule_path = _write_clean_rule(tmp_path)
    with patch("graft.cli.main.logging.basicConfig") as mock_basic_config:
        exit_code = main(["lint", str(rule_path), "--rules-dir", str(tmp_path / "rulesets")])
    assert exit_code == 0
    assert logging.Formatter.converter is time.gmtime
    mock_basic_config.assert_called_once_with(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
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


def test_main_lint_treats_rule_named_managed_yaml_as_custom_rule(tmp_path: Path) -> None:
    custom_dir = tmp_path / "rulesets" / "siem_alpha" / "custom"
    custom_dir.mkdir(parents=True)
    rule_file = custom_dir / "managed.yaml"
    rule_file.write_text(
        'metadata:\n  id: "11111111-2222-3333-4444-555555555555"\n  name: "managed"\n'
        '  description: "Custom rule named managed.yaml"\n  owners: ["SOC"]\n'
        '  mitre:\n    execution:\n      - "T1059"\n'
        '  tags: ["test"]\n  references: ["Internal reference"]\n'
        'logic: |\n  events:\n    $e.metadata.event_type = "USER_LOGIN"\n  condition:\n    $e\n'
        'deployment:\n  run_frequency: "live"\n'
        "  enabled: true\n  alerting: true\n"
        'runbook:\n  context: "Context"\n'
        '  triage: "Triage"\n  response: "Response"\n'
        "tests: []\n",
        encoding="utf-8",
    )
    exit_code = main(["lint", str(rule_file), "--rules-dir", str(tmp_path / "rulesets")])
    assert exit_code == 0


def test_main_lint_and_export_discover_yml_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    custom_dir = tmp_path / "rulesets" / "siem_alpha" / "custom"
    custom_dir.mkdir(parents=True)
    rule_yml = custom_dir / "rule_one.yml"
    rule_yaml = custom_dir / "rule_two.yaml"

    shared_body = (
        'metadata:\n  id: "11111111-2222-3333-4444-555555555555"\n  name: "dup_yml_rule"\n'
        '  description: "Rule using yml extension"\n  owners: ["SOC"]\n'
        '  mitre:\n    execution:\n      - "T1059"\n'
        '  tags: ["test"]\n  references: ["Internal reference"]\n'
        'logic: |\n  events:\n    $e.metadata.event_type = "USER_LOGIN"\n  condition:\n    $e\n'
        'deployment:\n  run_frequency: "live"\n'
        "  enabled: true\n  alerting: true\n"
        'runbook:\n  context: "Context"\n'
        '  triage: "Triage"\n  response: "Response"\n'
        "tests: []\n"
    )
    rule_yml.write_text(shared_body, encoding="utf-8")

    exit_code_export = main(
        ["export", "catalog", "--format", "json", "--rules-dir", str(tmp_path / "rulesets")]
    )
    assert exit_code_export == 0
    exported = json.loads(capsys.readouterr().out)
    assert len(exported) == 1
    assert exported[0]["name"] == "dup_yml_rule"

    rule_yaml.write_text(shared_body, encoding="utf-8")
    exit_code_lint = main(["lint", str(rule_yaml), "--rules-dir", str(tmp_path / "rulesets")])
    assert exit_code_lint == 1
    assert "Duplicate rule metadata.id" in capsys.readouterr().err


def test_engine_test_explicit_managed_rule_skips_cleanly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    managed_dir = tmp_path / "rulesets" / "siem_alpha" / "managed"
    managed_dir.mkdir(parents=True)
    managed_rule = managed_dir / "managed_with_tests.yaml"
    managed_rule.write_text(
        'metadata:\n  id: "11111111-2222-3333-4444-555555555555"\n  name: "managed_with_tests"\n'
        '  description: "Registered managed rule with test vector"\n  owners: ["SOC"]\n'
        '  mitre:\n    execution:\n      - "T1059"\n'
        '  tags: ["test"]\n  references: ["Internal reference"]\n'
        'managed:\n  id: "433faf9e-4d51-f284-c35b-009528ecff05"\n'
        'runbook:\n  context: "Context"\n'
        '  triage: "Triage"\n  response: "Response"\n'
        'tests:\n  - id: "t1"\n    description: "test"\n    expect: 1\n    events:\n'
        '      - timestamp: "2026-09-18T00:00:00Z"\n        payload:\n          k: "v"\n',
        encoding="utf-8",
    )
    manifest = EngineManifest(
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
    controller = EngineCommandController(manifest, EngineRegistry())
    args = argparse.Namespace(
        engine_command="test",
        paths=[str(managed_rule)],
        require_staging=True,
        changed_only=False,
    )
    exit_code = controller.execute(args, json_output=True)
    assert exit_code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["success"] is True
    assert data["total"] == 0
    assert "skipped" not in data


def test_main_lint_duplicate_file_stem_in_same_engine_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    custom_dir = tmp_path / "rulesets" / "siem_alpha" / "custom"
    custom_dir.mkdir(parents=True)
    rule_yaml = custom_dir / "same_stem.yaml"
    rule_yml = custom_dir / "same_stem.yml"

    rule_yaml.write_text(
        'metadata:\n  id: "11111111-1111-1111-1111-111111111111"\n  name: "first_rule_name"\n'
        '  description: "First rule"\n  owners: ["SOC"]\n'
        '  mitre:\n    execution:\n      - "T1059"\n'
        '  tags: ["test"]\n  references: ["Internal reference"]\n'
        'logic: |\n  events:\n    $e.metadata.event_type = "USER_LOGIN"\n  condition:\n    $e\n'
        'deployment:\n  run_frequency: "live"\n'
        "  enabled: true\n  alerting: true\n"
        'runbook:\n  context: "Context"\n'
        '  triage: "Triage"\n  response: "Response"\n'
        "tests: []\n",
        encoding="utf-8",
    )
    rule_yml.write_text(
        'metadata:\n  id: "22222222-2222-2222-2222-222222222222"\n  name: "second_rule_name"\n'
        '  description: "Second rule"\n  owners: ["SOC"]\n'
        '  mitre:\n    execution:\n      - "T1059"\n'
        '  tags: ["test"]\n  references: ["Internal reference"]\n'
        'logic: |\n  events:\n    $e.metadata.event_type = "USER_LOGIN"\n  condition:\n    $e\n'
        'deployment:\n  run_frequency: "live"\n'
        "  enabled: true\n  alerting: true\n"
        'runbook:\n  context: "Context"\n'
        '  triage: "Triage"\n  response: "Response"\n'
        "tests: []\n",
        encoding="utf-8",
    )

    exit_code = main(["lint", "--rules-dir", str(tmp_path / "rulesets")])
    assert exit_code == 1
    assert "Duplicate rule filename stem 'same_stem'" in capsys.readouterr().err
