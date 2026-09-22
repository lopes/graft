import json
from pathlib import Path

import pytest

from graft.cli.main import main


def test_export_matrix_table_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["export", "matrix", "--format", "table"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "MITRE ATT&CK Detection Matrix" in captured.out
    assert "T1566.002" in captured.out
    assert "T1098.001" in captured.out


def test_export_matrix_navigator_json_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["export", "matrix", "--format", "navigator"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["domain"] == "enterprise-attack"
    assert data["versions"]["attack"] == "19.2"
    assert data["versions"]["navigator"] == "5.2.0"
    assert data["versions"]["layer"] == "4.5"
    assert data["gradient"]["colors"] == ["#ffffff", "#008744"]
    tech_ids = [t["techniqueID"] for t in data["techniques"]]
    assert "T1566.002" in tech_ids


def test_export_matrix_engine_and_color_flags(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["export", "matrix", "--engine", "secops", "--color", "#2e7d32"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["name"] == "Graft Detection Coverage (secops)"
    assert data["gradient"]["colors"] == ["#ffffff", "#2e7d32"]
    assert len(data["techniques"]) >= 1
    t0 = data["techniques"][0]
    assert t0["tactic"] != ""
    assert any(m["name"] == "engine" and "secops" in m["value"] for m in t0["metadata"])
    assert len(t0["links"]) >= 1


def test_export_matrix_out_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out_file = tmp_path / "matrix.json"
    exit_code = main(["export", "matrix", "--format", "navigator", "--out", str(out_file)])
    assert exit_code == 0
    assert out_file.is_file()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["domain"] == "enterprise-attack"


def test_export_catalog_table_default_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["export", "catalog"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Rule Name" in captured.out
    assert "workspace_nrd_possible_phishing" in captured.out
    assert "secops" in captured.out
    assert "enabled" in captured.out


def test_export_catalog_markdown_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["export", "catalog", "--format", "markdown"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "| Rule Name | Engine | Status | MITRE ATT&CK |" in captured.out
    assert "`workspace_nrd_possible_phishing`" in captured.out
    assert "`gcp_iam_service_account_key_create`" in captured.out


def test_export_catalog_csv_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["export", "catalog", "--format", "csv"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "id,name,engine,rule_type,status,description,mitre_attack" in captured.out
    assert "workspace_nrd_possible_phishing" in captured.out
    assert "TA0001:T1566.002" in captured.out


def test_export_catalog_json_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["export", "catalog", "--format", "json"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    rule_names = [r["name"] for r in data]
    assert "workspace_nrd_possible_phishing" in rule_names
    assert "gcp_iam_service_account_key_create" in rule_names
    for r in data:
        assert "status" in r
        assert "mitre_attack" in r
        assert "severity" not in r


def test_export_catalog_out_file(tmp_path: Path) -> None:
    out_file = tmp_path / "catalog.csv"
    exit_code = main(["export", "catalog", "--format", "csv", "--out", str(out_file)])
    assert exit_code == 0
    assert out_file.is_file()
    content = out_file.read_text(encoding="utf-8")
    assert "workspace_nrd_possible_phishing" in content
