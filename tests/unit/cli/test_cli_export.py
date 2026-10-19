import json
from pathlib import Path

import pytest

from graft.cli.main import main


def _write_sample_rulesets(tmp_path: Path) -> Path:
    rules_dir = tmp_path / "rulesets"
    custom_dir = rules_dir / "siem_alpha" / "custom"
    managed_dir = rules_dir / "siem_alpha" / "managed"
    custom_dir.mkdir(parents=True, exist_ok=True)
    managed_dir.mkdir(parents=True, exist_ok=True)

    (custom_dir / "workspace_nrd_email_opened.yaml").write_text(
        """metadata:
  id: "11111111-1111-1111-1111-111111111111"
  name: "workspace_nrd_email_opened"
  description: "Detects newly registered domain email opened."
  owners:
    - "Joe Lopes"
  mitre:
    initial-access:
      - "T1566.002"
  tags:
    - "email"
  references:
    - "https://attack.mitre.org/techniques/T1566/002/"
logic: "event_type == 'EMAIL_OPENED'"
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

    (custom_dir / "gcp_service_account_key_created.yaml").write_text(
        """metadata:
  id: "22222222-2222-2222-2222-222222222222"
  name: "gcp_service_account_key_created"
  description: "Detects service account key creation."
  owners:
    - "Joe Lopes"
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
  alerting: false
  run_frequency: "live"
runbook:
  context: "Context"
  triage: "Triage"
  response: "Response"
tests: []
""",
        encoding="utf-8",
    )

    (managed_dir / "gcti_breach_network_indicator_matched.yaml").write_text(
        """metadata:
  id: "33333333-3333-3333-3333-333333333333"
  name: "gcti_breach_network_indicator_matched"
  description: "Detects network breach indicator matches."
  owners:
    - "Joe Lopes"
  mitre:
    command-and-control:
      - "T1071.001"
  tags:
    - "managed"
  references:
    - "https://attack.mitre.org/techniques/T1071/001/"
managed:
  id: "433faf9e-4d51-f284-c35b-009528ecff05"
runbook:
  context: "Context"
  triage: "Triage"
  response: "Response"
tests: []
""",
        encoding="utf-8",
    )
    return rules_dir


def test_export_matrix_table_stdout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rules_dir = _write_sample_rulesets(tmp_path)
    exit_code = main(["export", "matrix", "--format", "table", "--rules-dir", str(rules_dir)])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "MITRE ATT&CK Detection Matrix" in captured.out
    assert "T1566.002" in captured.out
    assert "T1098.001" in captured.out


def test_export_matrix_navigator_json_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rules_dir = _write_sample_rulesets(tmp_path)
    exit_code = main(["export", "matrix", "--format", "navigator", "--rules-dir", str(rules_dir)])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["domain"] == "enterprise-attack"
    assert tuple(int(p) for p in str(data["versions"]["attack"]).split(".")) >= (19, 2)
    assert data["versions"]["navigator"] == "5.2.0"
    assert data["versions"]["layer"] == "4.5"
    assert data["gradient"]["colors"] == ["#ffffff", "#008744"]
    tech_ids = [t["techniqueID"] for t in data["techniques"]]
    assert "T1566.002" in tech_ids


def test_export_matrix_engine_and_color_flags(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rules_dir = _write_sample_rulesets(tmp_path)
    exit_code = main(
        [
            "export",
            "matrix",
            "--engine",
            "siem_alpha",
            "--color",
            "#2e7d32",
            "--rules-dir",
            str(rules_dir),
        ]
    )
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["name"] == "Graft Detection Coverage (siem_alpha)"
    assert data["gradient"]["colors"] == ["#ffffff", "#2e7d32"]
    assert len(data["techniques"]) >= 1
    t0 = data["techniques"][0]
    assert t0["tactic"] != ""
    assert any(m["name"] == "engine" and "siem_alpha" in m["value"] for m in t0["metadata"])
    assert len(t0["links"]) >= 1


def test_export_matrix_out_file(tmp_path: Path) -> None:
    rules_dir = _write_sample_rulesets(tmp_path)
    out_file = tmp_path / "matrix.json"
    exit_code = main(
        [
            "export",
            "matrix",
            "--format",
            "navigator",
            "--rules-dir",
            str(rules_dir),
            "--out",
            str(out_file),
        ]
    )
    assert exit_code == 0
    assert out_file.is_file()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["domain"] == "enterprise-attack"


def test_export_catalog_table_default_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rules_dir = _write_sample_rulesets(tmp_path)
    exit_code = main(["export", "catalog", "--rules-dir", str(rules_dir)])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Rule Name" in captured.out
    assert "Type" in captured.out
    assert "Owners" in captured.out
    assert "Runbook" not in captured.out
    assert "workspace_nrd_email_opened" in captured.out
    assert "gcti_breach_network_indicator_matched" in captured.out
    assert "siem_alpha" in captured.out
    assert "custom" in captured.out
    assert "managed" in captured.out
    assert "enabled" in captured.out
    assert "silent" in captured.out


def test_export_catalog_markdown_stdout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rules_dir = _write_sample_rulesets(tmp_path)
    exit_code = main(["export", "catalog", "--format", "markdown", "--rules-dir", str(rules_dir)])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert (
        "| Rule Name | Engine | Type | Status | MITRE ATT&CK | Author | Owners | Owner Count |"
        in captured.out
    )
    assert "Runbook" not in captured.out
    assert "`workspace_nrd_email_opened`" in captured.out
    assert "`gcp_service_account_key_created`" in captured.out
    assert "`gcti_breach_network_indicator_matched`" in captured.out
    assert "Joe Lopes" in captured.out


def test_export_catalog_csv_stdout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rules_dir = _write_sample_rulesets(tmp_path)
    exit_code = main(["export", "catalog", "--format", "csv", "--rules-dir", str(rules_dir)])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert (
        "id,name,engine,rule_type,status,description,mitre_attack,tags,author,owners,owner_count,"
        in captured.out
    )
    assert "has_runbook" not in captured.out
    assert "workspace_nrd_email_opened" in captured.out
    assert "gcti_breach_network_indicator_matched" in captured.out
    assert "TA0001:T1566.002" in captured.out


def test_export_catalog_json_stdout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rules_dir = _write_sample_rulesets(tmp_path)
    exit_code = main(["export", "catalog", "--format", "json", "--rules-dir", str(rules_dir)])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    rule_names = [r["name"] for r in data]
    assert "workspace_nrd_email_opened" in rule_names
    assert "gcp_service_account_key_created" in rule_names
    assert "gcti_breach_network_indicator_matched" in rule_names
    rule_types = {r["name"]: r["rule_type"] for r in data}
    assert rule_types["workspace_nrd_email_opened"] == "custom"
    assert rule_types["gcti_breach_network_indicator_matched"] == "managed"
    for r in data:
        assert "status" in r
        assert "mitre_attack" in r
        assert "author" in r
        assert "owners" in r
        assert isinstance(r["owners"], list)
        assert "owner_count" in r
        assert r["owner_count"] == len(r["owners"])
        assert "has_runbook" not in r
        assert "severity" not in r


def test_export_catalog_out_file(tmp_path: Path) -> None:
    rules_dir = _write_sample_rulesets(tmp_path)
    out_file = tmp_path / "catalog.csv"
    exit_code = main(
        [
            "export",
            "catalog",
            "--format",
            "csv",
            "--rules-dir",
            str(rules_dir),
            "--out",
            str(out_file),
        ]
    )
    assert exit_code == 0
    assert out_file.is_file()
    content = out_file.read_text(encoding="utf-8")
    assert "workspace_nrd_email_opened" in content


def test_export_datasets_table_json_and_csv_with_ttl_filtering(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ds_dir = tmp_path / "datasets"
    ds_dir.mkdir(parents=True)
    (ds_dir / "known_scanner_ips.yaml").write_text(
        """metadata:
  name: "known_scanner_ips"
  description: "Authorized vulnerability scanner IP addresses"
  owners:
    - "Detection Engineering"
  tags:
    - "network"
  references:
    - "https://internal.wiki/scanners"
values:
  - "198.51.100.10"
  - "198.51.100.20" # temporary scanner ttl:2020-01-01
  - "198.51.100.30" # future scanner ttl:2099-12-31
""",
        encoding="utf-8",
    )

    rc_table = main(["export", "datasets", "--datasets-dir", str(ds_dir)])
    assert rc_table == 0
    table_out = capsys.readouterr().out
    assert "known_scanner_ips" in table_out
    assert "Authorized vulnerability scanner IP addresses" in table_out

    rc_json = main(["--json", "export", "datasets", "--datasets-dir", str(ds_dir)])
    assert rc_json == 0
    json_data = json.loads(capsys.readouterr().out)
    assert isinstance(json_data, list)
    assert len(json_data) == 1
    assert json_data[0]["name"] == "known_scanner_ips"
    assert json_data[0]["value_count"] == 2
    assert json_data[0]["values"] == ["198.51.100.10", "198.51.100.30"]

    rc_csv = main(["export", "datasets", "--format", "csv", "--datasets-dir", str(ds_dir)])
    assert rc_csv == 0
    csv_out = capsys.readouterr().out
    assert "name,description,owners,tags,value_count,values" in csv_out
    assert "known_scanner_ips" in csv_out
    assert "198.51.100.10;198.51.100.30" in csv_out
    assert "198.51.100.20" not in csv_out


def test_export_navigator_and_mitre_aliases_with_filters_and_enrich(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rules_dir = _write_sample_rulesets(tmp_path)
    rc = main(
        [
            "export",
            "navigator",
            "--platform",
            "IaaS",
            "--enrich",
            "--include-gaps",
            "--rules-dir",
            str(rules_dir),
        ]
    )
    assert rc == 0
    layer = json.loads(capsys.readouterr().out)
    assert layer["filters"]["platforms"] == ["IaaS"]
    assert any(t["score"] == 0 for t in layer["techniques"])

    rc_alias = main(
        [
            "export",
            "mitre",
            "--platform",
            "IaaS",
            "--rules-dir",
            str(rules_dir),
        ]
    )
    assert rc_alias == 0
    layer_alias = json.loads(capsys.readouterr().out)
    assert layer_alias["filters"]["platforms"] == ["IaaS"]


def test_mitre_cli_coverage_gaps_inspect_and_update_check(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from unittest.mock import patch

    rules_dir = _write_sample_rulesets(tmp_path)

    # 1. graft --json mitre coverage --enrich --tag iam
    rc_cov = main(
        [
            "--json",
            "mitre",
            "coverage",
            "--tag",
            "iam",
            "--enrich",
            "--rules-dir",
            str(rules_dir),
        ]
    )
    assert rc_cov == 0
    cov_data = json.loads(capsys.readouterr().out)
    assert cov_data["success"] is True
    assert cov_data["covered_techniques"] == 1
    assert cov_data["techniques"][0]["technique_id"] == "T1098.001"
    assert "detection_strategies" in cov_data["techniques"][0]

    # 2. graft --json mitre gaps --platform IaaS --top 5 and --infer-scope
    rc_gaps = main(
        [
            "--json",
            "mitre",
            "gaps",
            "--platform",
            "IaaS",
            "--top",
            "5",
            "--rules-dir",
            str(rules_dir),
        ]
    )
    assert rc_gaps == 0
    gaps_data = json.loads(capsys.readouterr().out)
    assert gaps_data["success"] is True
    assert len(gaps_data["gaps"]) <= 5
    assert "inferred_scope" in gaps_data

    rc_infer = main(
        [
            "--json",
            "mitre",
            "gaps",
            "--infer-scope",
            "--top",
            "5",
            "--rules-dir",
            str(rules_dir),
        ]
    )
    assert rc_infer == 0
    infer_data = json.loads(capsys.readouterr().out)
    assert infer_data["success"] is True
    assert infer_data["scope"]["infer_scope"] == "true"

    # 3. graft --json mitre inspect T1098.001 --analytics --platform IaaS
    rc_insp = main(
        [
            "--json",
            "mitre",
            "inspect",
            "T1098.001",
            "--analytics",
            "--platform",
            "IaaS",
            "--rules-dir",
            str(rules_dir),
        ]
    )
    assert rc_insp == 0
    insp_data = json.loads(capsys.readouterr().out)
    assert insp_data["success"] is True
    assert insp_data["items"][0]["id"] == "T1098.001"
    assert "analytics" in insp_data["items"][0]

    # 4. graft mitre update --check
    with patch(
        "graft.cli.commands_core.check_upstream_mitre_version",
        return_value={
            "current_version": "19.2",
            "latest_version": "20.0",
            "update_available": True,
            "latest_url": "https://example.com/20.0.json",
            "offline": False,
        },
    ):
        rc_chk = main(["mitre", "update", "--check"])
        assert rc_chk == 0
        chk_out = capsys.readouterr()
        assert "20.0" in chk_out.out or "20.0" in chk_out.err
