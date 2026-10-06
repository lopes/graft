import json
from pathlib import Path

import pytest

from graft.cli.commands_core import execute_lint
from graft.cli.main import main
from graft.cli.scaffold import ScaffoldError, scaffold_dataset
from graft.core.loader import load_dataset_from_yaml


def _write_dataset(path: Path, name: str = "known_scanner_ips") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"""metadata:
  name: "{name}"
  description: "Known scanner IP addresses."
  owners:
    - "SOC"
  tags:
    - "network"
  references:
    - "https://lopes.id/log/detection-rules-netscan-portscan/"
values:
  - "10.10.0.50" # Internal scanner
""",
        encoding="utf-8",
    )
    return path


def _write_custom_rule(path: Path, name: str, logic: str, rule_uuid: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"""metadata:
  id: "{rule_uuid}"
  name: "{name}"
  description: "Test custom rule referencing dataset."
  owners:
    - "SOC"
  mitre:
    discovery:
      - "T1046"
  tags:
    - "network"
  references:
    - "https://attack.mitre.org/techniques/T1046/"
logic: |
{logic}
deployment:
  enabled: true
  alerting: true
  run_frequency: "live"
runbook:
  context: "Test context."
  triage: "1. Triage step."
  response: "1. Response step."
tests: []
""",
        encoding="utf-8",
    )
    return path


def test_lint_dataset_file_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ds_path = _write_dataset(tmp_path / "datasets" / "known_scanner_ips.yaml")
    exit_code = main(["--json", "lint", str(ds_path)])
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["success"] is True
    assert payload["results"][0]["type"] == "dataset"
    assert payload["results"][0]["valid"] is True


def test_lint_scans_both_rulesets_and_datasets_by_default(tmp_path: Path) -> None:
    datasets_dir = tmp_path / "datasets"
    rules_dir = tmp_path / "rulesets"
    _write_dataset(datasets_dir / "known_scanner_ips.yaml")
    # Archived datasets with malformed content must be ignored
    archived = datasets_dir / "_archived" / "old_bad.yaml"
    archived.parent.mkdir(parents=True)
    archived.write_text("not: valid: dataset", encoding="utf-8")

    _write_custom_rule(
        rules_dir / "siem_alpha" / "custom" / "multiple_hosts_scanned.yaml",
        name="multiple_hosts_scanned",
        logic=(
            "  events:\n"
            '    $e.metadata.event_type = "NETWORK_CONNECTION"\n'
            "    not $e.principal.ip in %known_scanner_ips.value\n"
            "  condition:\n"
            "    $e"
        ),
        rule_uuid="11111111-2222-3333-4444-555555555555",
    )

    rc = execute_lint(
        rules_dir=str(rules_dir),
        datasets_dir=str(datasets_dir),
    )
    assert rc == 0


def test_lint_delegates_dataset_reference_validation_to_engine_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from unittest.mock import MagicMock

    datasets_dir = tmp_path / "datasets"
    rules_dir = tmp_path / "rulesets"
    _write_dataset(datasets_dir / "known_scanner_ips.yaml")

    bad_rule = _write_custom_rule(
        rules_dir / "siem_alpha" / "custom" / "bad_ref_rule.yaml",
        name="bad_ref_rule",
        logic="  query referencing %known_scanner_ips.wrong_col",
        rule_uuid="11111111-2222-3333-4444-555555555551",
    )

    mock_adapter = MagicMock()
    mock_adapter.validate_rule_dataset_references.side_effect = ValueError(
        "Dataset 'known_scanner_ips' must be referenced via 'known_scanner_ips.value'"
    )

    monkeypatch.setattr(
        "graft.cli.commands_core.EngineRegistry.get",
        lambda self, name: MagicMock(name=name),
    )
    monkeypatch.setattr(
        "graft.cli.commands_core.EngineRegistry.load_adapter",
        lambda self, name, env="staging": mock_adapter,
    )

    rc = execute_lint(
        paths=[str(bad_rule)],
        rules_dir=str(rules_dir),
        datasets_dir=str(datasets_dir),
    )
    assert rc == 1
    err_out = capsys.readouterr().err
    assert "known_scanner_ips.value" in err_out
    mock_adapter.validate_rule_dataset_references.assert_called_once()


def test_scaffold_dataset_via_function_and_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "graft.cli.scaffold._resolve_default_owner",
        lambda cwd=None: "Joe Lopes",
    )
    ds_path = scaffold_dataset("known_scanner_ips", project_root=tmp_path)
    assert ds_path == tmp_path / "datasets" / "known_scanner_ips.yaml"
    assert ds_path.is_file()

    loaded = load_dataset_from_yaml(ds_path)
    assert loaded.metadata.name == "known_scanner_ips"
    assert loaded.metadata.owners == ("Joe Lopes",)
    assert len(loaded.values) >= 1

    with pytest.raises(ScaffoldError, match="already exists"):
        scaffold_dataset("known_scanner_ips", project_root=tmp_path)

    with pytest.raises(ScaffoldError, match="Invalid dataset name"):
        scaffold_dataset("1invalid_start", project_root=tmp_path)

    custom_out = tmp_path / "datasets" / "security_assessment_ips.yaml"
    exit_code = main(
        ["--json", "new", "dataset", "security_assessment_ips", "--out", str(custom_out)]
    )
    assert exit_code == 0
    out_data = json.loads(capsys.readouterr().out)
    assert out_data["success"] is True
    assert Path(out_data["path"]) == custom_out
