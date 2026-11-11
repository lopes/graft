from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from graft.cli.main import main
from graft.core.models.compiler import CompilationResult
from graft.engines.gti.adapter import GTIAdapter


def test_gti_engine_registered_in_cli_engines_json(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = main(["--json", "engines"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    engines_by_name = {e["name"]: e for e in out["engines"]}
    assert "gti" in engines_by_name
    gti_info = engines_by_name["gti"]
    assert gti_info["capabilities"] == {
        "custom_rules": True,
        "datasets": False,
        "syntax_verification": True,
        "managed_rules": False,
        "replay_testing": True,
    }


def test_gti_cli_new_and_render_and_test_offline(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rule_out = tmp_path / "rulesets" / "gti" / "custom" / "test_phish_url.yaml"
    rc_new = main(["--json", "gti", "new", "test_phish_url", "--out", str(rule_out)])
    assert rc_new == 0
    new_payload = json.loads(capsys.readouterr().out)
    assert new_payload["success"] is True
    assert rule_out.is_file()

    rc_lint = main(["--json", "lint", str(rule_out)])
    assert rc_lint == 0
    lint_payload = json.loads(capsys.readouterr().out)
    assert lint_payload["success"] is True

    rc_render = main(["--json", "gti", "render", str(rule_out)])
    assert rc_render == 0
    render_payload = json.loads(capsys.readouterr().out)
    assert render_payload["success"] is True
    rendered = render_payload["rules"][0]["rendered"]
    assert "rule test_phish_url {" in rendered
    assert 'graft_id = "' in rendered

    rc_test = main(["--json", "gti", "test", str(rule_out)])
    assert rc_test == 0
    test_payload = json.loads(capsys.readouterr().out)
    assert test_payload["success"] is True


def test_gti_cli_verify_and_diff_and_apply_with_mocked_ports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    rule_out = tmp_path / "rulesets" / "gti" / "custom" / "test_livehunt_rule.yaml"
    main(["--json", "gti", "new", "test_livehunt_rule", "--out", str(rule_out)])
    capsys.readouterr()

    with patch.object(
        GTIAdapter,
        "get_compiler",
    ) as mock_get_compiler:
        mock_compiler = mock_get_compiler.return_value
        mock_compiler.verify_rule.return_value = CompilationResult(success=True)
        rc_verify = main(["--json", "gti", "verify", str(rule_out)])
        assert rc_verify == 0
        verify_out = json.loads(capsys.readouterr().out)
        assert verify_out["success"] is True

    with patch.object(
        GTIAdapter,
        "get_deployer",
    ) as mock_get_deployer:
        mock_deployer = mock_get_deployer.return_value
        mock_deployer.list_rules.return_value = ()
        mock_deployer.create_rule.return_value = "gti_rs_001"

        rc_diff = main(["--json", "gti", "diff", "--all"])
        assert rc_diff == 2
        diff_out = json.loads(capsys.readouterr().out)
        assert diff_out["custom"]["has_changes"] is True
        assert diff_out["custom"]["rules_to_create"] == ["test_livehunt_rule"]

        rc_apply = main(["--json", "gti", "apply", "--all"])
        assert rc_apply == 0
        apply_out = json.loads(capsys.readouterr().out)
        assert apply_out["success"] is True
        mock_deployer.create_rule.assert_called_once()


def test_gti_schema_and_yara_adversarial_inputs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bad_gti_rule = tmp_path / "rulesets" / "gti" / "custom" / "bad_match_type.yaml"
    bad_gti_rule.parent.mkdir(parents=True)
    bad_gti_rule.write_text(
        """metadata:
  id: "8f14e45f-ceea-467a-a124-000000000099"
  name: "bad_match_type"
  description: "Invalid subtype value"
  owners: ["SOC"]
  mitre:
    initial-access: ["T1566.002"]
  tags: ["gti"]
  references: ["https://example.com"]
logic: |
  import "vt"
  condition:
    vt.net.url.new_url
deployment:
  type: "livehunt"
  subtype: "ip"
  enabled: true
runbook:
  context: "ctx"
  triage: "tri"
  response: "resp"
tests: []
""",
        encoding="utf-8",
    )

    rc = main(["--json", "lint", str(bad_gti_rule)])
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["success"] is False
    assert "subtype" in out["results"][0]["errors"][0]

    bad_brace_rule = tmp_path / "rulesets" / "gti" / "custom" / "bad_brace_rule.yaml"
    bad_brace_rule.write_text(
        """metadata:
  id: "8f14e45f-ceea-467a-a124-000000000098"
  name: "bad_brace_rule"
  description: "Unbalanced parentheses in YARA condition"
  owners: ["SOC"]
  mitre:
    initial-access: ["T1566.002"]
  tags: ["gti"]
  references: ["https://example.com"]
logic: |
  import "vt"
  condition:
    (vt.net.url.new_url
deployment:
  type: "livehunt"
  subtype: "url"
  enabled: false
runbook:
  context: "ctx"
  triage: "tri"
  response: "resp"
tests: []
""",
        encoding="utf-8",
    )

    rc_verify = main(["--json", "gti", "verify", str(bad_brace_rule)])
    assert rc_verify == 1
    verify_out = json.loads(capsys.readouterr().out)
    assert verify_out["success"] is False
    assert "Unbalanced parentheses" in verify_out["diagnostics"][0]["error"]

    bad_retro_rule = tmp_path / "rulesets" / "gti" / "custom" / "bad_retro_rule.yaml"
    bad_retro_rule.write_text(
        """metadata:
  id: "8f14e45f-ceea-467a-a124-000000000097"
  name: "bad_retro_rule"
  description: "Retrohunt rule with livehunt daily_limit field"
  owners: ["SOC"]
  mitre:
    initial-access: ["T1566.002"]
  tags: ["gti"]
  references: ["https://example.com"]
logic: |
  import "vt"
  condition:
    vt.metadata.new_file
deployment:
  type: "retrohunt"
  enabled: false
  corpus: "main"
  daily_limit: 50
runbook:
  context: "ctx"
  triage: "tri"
  response: "resp"
tests: []
""",
        encoding="utf-8",
    )
    rc_retro = main(["--json", "lint", str(bad_retro_rule)])
    assert rc_retro == 1
    retro_out = json.loads(capsys.readouterr().out)
    assert retro_out["success"] is False

    missing_corpus_rule = tmp_path / "rulesets" / "gti" / "custom" / "missing_corpus_rule.yaml"
    missing_corpus_rule.write_text(
        """metadata:
  id: "8f14e45f-ceea-467a-a124-000000000096"
  name: "missing_corpus_rule"
  description: "Retrohunt rule missing required corpus field"
  owners: ["SOC"]
  mitre:
    initial-access: ["T1566.002"]
  tags: ["gti"]
  references: ["https://example.com"]
logic: |
  import "vt"
  condition:
    vt.metadata.new_file
deployment:
  type: "retrohunt"
  enabled: false
runbook:
  context: "ctx"
  triage: "tri"
  response: "resp"
tests: []
""",
        encoding="utf-8",
    )
    rc_missing_corpus = main(["--json", "lint", str(missing_corpus_rule)])
    assert rc_missing_corpus == 1
    missing_corpus_out = json.loads(capsys.readouterr().out)
    assert missing_corpus_out["success"] is False
    assert "corpus" in missing_corpus_out["results"][0]["errors"][0]
