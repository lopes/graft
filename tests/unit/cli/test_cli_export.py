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
    assert data["versions"]["navigator"] == "4.5"
    tech_ids = [t["techniqueID"] for t in data["techniques"]]
    assert "T1566.002" in tech_ids


def test_export_matrix_out_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out_file = tmp_path / "matrix.json"
    exit_code = main(["export", "matrix", "--format", "navigator", "--out", str(out_file)])
    assert exit_code == 0
    assert out_file.is_file()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["domain"] == "enterprise-attack"


def test_export_catalog_markdown_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["export", "catalog", "--format", "markdown"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "| Rule Name | Engine |" in captured.out
    assert "`workspace_nrd_possible_phishing`" in captured.out
    assert "`gcp_iam_service_account_key_create`" in captured.out


def test_export_catalog_csv_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["export", "catalog", "--format", "csv"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "id,name,engine,rule_type" in captured.out
    assert "workspace_nrd_possible_phishing" in captured.out
    assert "gcp_iam_service_account_key_create" in captured.out


def test_export_catalog_json_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["export", "catalog", "--format", "json"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    rule_names = [r["name"] for r in data]
    assert "workspace_nrd_possible_phishing" in rule_names
    assert "gcp_iam_service_account_key_create" in rule_names


def test_export_catalog_out_file(tmp_path: Path) -> None:
    out_file = tmp_path / "catalog.csv"
    exit_code = main(["export", "catalog", "--format", "csv", "--out", str(out_file)])
    assert exit_code == 0
    assert out_file.is_file()
    content = out_file.read_text(encoding="utf-8")
    assert "workspace_nrd_possible_phishing" in content
