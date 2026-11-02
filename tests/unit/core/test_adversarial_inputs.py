import argparse
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from graft.cli.commands_core import execute_lint
from graft.cli.engine_controller import EngineCommandController
from graft.core.engine_registry import EngineRegistry
from graft.core.loader import (
    DatasetLoadError,
    RuleLoadError,
    load_dataset_from_str,
    load_dataset_from_yaml,
    load_rule_from_str,
    load_rule_from_yaml,
)
from graft.core.models.engine import EngineCapabilities, EngineManifest

HOSTILE_YAML_STRINGS = (
    "",
    "   \n\t  ",
    "null",
    "true",
    "42",
    "- item1\n- item2",
    "metadata: [unterminated",
    "metadata: null\nlogic: null\ndeployment: null\nrunbook: null\ntests: null",
    "metadata:\n  id: 123\n  name: [1, 2]\n  description: {a: b}",
    "metadata:\n  name: valid_name\n  description: desc\nvalues: [unclosed",
    "metadata: 123\nvalues: 456",
)


@pytest.mark.parametrize("payload", HOSTILE_YAML_STRINGS)
def test_load_rule_from_str_never_crashes_on_hostile_input(payload: str) -> None:
    with pytest.raises(RuleLoadError):
        load_rule_from_str(payload, validate_mitre=False)


@pytest.mark.parametrize("payload", HOSTILE_YAML_STRINGS)
def test_load_dataset_from_str_never_crashes_on_hostile_input(payload: str) -> None:
    with pytest.raises(DatasetLoadError):
        load_dataset_from_str(payload)


def test_load_rule_from_yaml_handles_invalid_utf8_bytes_gracefully(tmp_path: Path) -> None:
    bad_file = tmp_path / "corrupt_rule.yaml"
    bad_file.write_bytes(b"\xff\xfe\x00\x80invalid utf-8")

    with pytest.raises(RuleLoadError, match="UTF-8"):
        load_rule_from_yaml(bad_file)


def test_load_dataset_from_yaml_handles_invalid_utf8_bytes_gracefully(tmp_path: Path) -> None:
    bad_file = tmp_path / "corrupt_dataset.yaml"
    bad_file.write_bytes(b"\xff\xfe\x00\x80invalid utf-8")

    with pytest.raises(DatasetLoadError, match="UTF-8"):
        load_dataset_from_yaml(bad_file)


def test_execute_lint_json_output_on_missing_path_emits_valid_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing_path = tmp_path / "does_not_exist.yaml"
    rc = execute_lint(paths=[str(missing_path)], json_output=True)
    assert rc == 1

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["success"] is False
    assert "error" in payload
    assert "does_not_exist.yaml" in payload["error"]


def test_engine_controller_json_output_on_managed_errors_and_unknown_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = EngineManifest(
        name="mock_siem",
        display_name="Mock SIEM",
        description="Mock adapter",
        adapter_class="mock:Adapter",
        capabilities=EngineCapabilities(
            datasets=True,
            custom_rules=True,
            managed_rules=True,
            syntax_verification=True,
            replay_testing=True,
        ),
        environments=("staging", "production"),
    )
    registry = MagicMock(spec=EngineRegistry)
    adapter = MagicMock()
    adapter.get_managed.return_value = None
    registry.load_adapter.return_value = adapter

    controller = EngineCommandController(manifest=manifest, registry=registry)

    # 1. managed_port is None with --json
    args_no_port = argparse.Namespace(engine_command="managed", managed_command="diff")
    rc = controller.execute(args_no_port, json_output=True)
    assert rc == 1
    payload_no_port = json.loads(capsys.readouterr().out)
    assert payload_no_port["success"] is False
    assert "Managed content not supported" in payload_no_port["error"]

    # 2. managed apply when manifest file is missing with --json
    adapter.get_managed.return_value = MagicMock()
    adapter.load_managed_manifest.return_value = None
    args_apply_missing = argparse.Namespace(
        engine_command="managed",
        managed_command="apply",
        out=str(tmp_path / "missing_index.yaml"),
    )
    rc2 = controller.execute(args_apply_missing, json_output=True)
    assert rc2 == 1
    payload_apply = json.loads(capsys.readouterr().out)
    assert payload_apply["success"] is False
    assert "error" in payload_apply

    # 3. unknown engine command with --json
    args_unknown = argparse.Namespace(engine_command="nonexistent_subcommand")
    rc3 = controller.execute(args_unknown, json_output=True)
    assert rc3 == 1
    payload_unknown = json.loads(capsys.readouterr().out)
    assert payload_unknown["success"] is False
    assert "nonexistent_subcommand" in payload_unknown["error"]


def test_mitre_stix_parser_and_cli_adversarial_inputs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from graft.cli.main import main
    from graft.core.validation.mitre_validator import (
        parse_attack_analytics_bundle,
        parse_attack_stix_bundle,
    )

    corrupted_bundle = {
        "objects": [
            123,
            None,
            "bad",
            {"type": "attack-pattern", "external_references": "not_a_list"},
            {"type": "relationship", "relationship_type": "uses", "source_ref": 123},
            {
                "type": "x-mitre-analytic",
                "external_references": [{"source_name": "mitre-attack", "external_id": "AN9999"}],
                "name": "Test",
                "x_mitre_log_source_references": "bad",
                "x_mitre_mutable_elements": "bad",
            },
        ]
    }
    res_core = parse_attack_stix_bundle(corrupted_bundle)
    assert "T0000" in res_core["techniques"]
    res_an = parse_attack_analytics_bundle(corrupted_bundle)
    assert "AN9999" in res_an["analytics"]

    rc_bad_inspect = main(["--json", "mitre", "inspect", "UNKNOWN_ENTITY_999"])
    assert rc_bad_inspect == 1
    err_inspect = json.loads(capsys.readouterr().out)
    assert err_inspect["success"] is False
    assert "Unknown MITRE entity" in err_inspect["error"]

    rc_bad_gaps = main(["--json", "mitre", "gaps", "--platform", "BeOS_Invalid"])
    assert rc_bad_gaps == 1
    err_gaps = json.loads(capsys.readouterr().out)
    assert err_gaps["success"] is False
    assert "Unknown MITRE platform" in err_gaps["error"]


def test_env_non_utf8_and_single_quote_and_main_json_parse_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from graft.cli.main import main
    from graft.core.env import load_env_file

    bad_env = tmp_path / ".env"
    bad_env.write_bytes(b"\xff\xfeINVALID_UTF8=1\n")
    assert load_env_file(path=bad_env) == {}

    quote_env = tmp_path / "quote.env"
    quote_env.write_text('SINGLE_QUOTE_VAL="\n', encoding="utf-8")
    monkeypatch.delenv("SINGLE_QUOTE_VAL", raising=False)
    loaded = load_env_file(path=quote_env)
    assert loaded["SINGLE_QUOTE_VAL"] == '"'

    rc = main(["--json", "--nonexistent-flag-xyz"])
    assert rc != 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["success"] is False
    assert "error" in payload


def test_loader_missing_schema_duplicate_test_ids_and_yaml_aliases() -> None:
    valid_rule_yaml = """metadata:
  id: "11111111-1111-1111-1111-111111111111"
  name: "sample_rule"
  description: "Sample rule description"
  owners: ["team-a"]
  mitre:
    execution: ["T1059"]
  tags: ["cloud"]
  references: ["https://example.com"]
logic: "condition: true"
deployment:
  enabled: true
  alerting: true
  run_frequency: "live"
runbook:
  context: "ctx"
  triage: "tri"
  response: "res"
tests:
  - id: "dup_vec"
    description: "first"
    expect: 1
    events:
      - timestamp: "2026-01-01T00:00:00Z"
        payload:
          host: "web-01"
  - id: "dup_vec"
    description: "second"
    expect: 1
    events:
      - timestamp: "2026-01-01T00:00:01Z"
        payload:
          host: "web-02"
"""
    with pytest.raises(RuleLoadError):
        load_rule_from_str(valid_rule_yaml, schema_name="nonexistent_schema_xyz")

    with pytest.raises(RuleLoadError, match="Duplicate test vector id"):
        load_rule_from_str(valid_rule_yaml, validate_mitre=False)

    alias_ds_yaml = """metadata:
  name: "allowed_hosts"
  description: "Allowed hosts list"
  owners: ["team-a"]
  tags:
    - &anchor_ip "network"
  references: ["https://example.com"]
values:
  - *anchor_ip
"""
    with pytest.raises(DatasetLoadError):
        load_dataset_from_str(alias_ds_yaml, schema_name="nonexistent_schema_xyz")

    with pytest.raises(DatasetLoadError, match=r"anchor|alias"):
        load_dataset_from_str(alias_ds_yaml)


def test_pull_path_traversal_guard_and_pull_all_includes_datasets(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from graft.core.models.dataset import DatasetEnvelope, DatasetMetadata
    from graft.core.models.rule import BaseDeploymentConfig, RuleEnvelope, RuleMetadata, Runbook

    manifest = EngineManifest(
        name="siem_alpha",
        display_name="SIEM Alpha",
        description="Mock adapter",
        adapter_class="mock:Adapter",
        capabilities=EngineCapabilities(
            datasets=True,
            custom_rules=True,
            managed_rules=False,
            syntax_verification=True,
            replay_testing=False,
        ),
        environments=("staging", "production"),
    )
    registry = MagicMock(spec=EngineRegistry)
    adapter = MagicMock()
    deployer = MagicMock()
    ds_port = MagicMock()
    adapter.get_deployer.return_value = deployer
    adapter.get_managed.return_value = None
    adapter.get_dataset.return_value = ds_port
    adapter.deconstruct_rule.side_effect = lambda r: r
    registry.load_adapter.return_value = adapter

    controller = EngineCommandController(manifest=manifest, registry=registry)

    # 1. Path traversal in remote dataset name rejected
    evil_ds = DatasetEnvelope(
        metadata=DatasetMetadata(name="../evil_dataset", description="evil"),
        values=("a",),
    )
    ds_port.list_datasets.return_value = (evil_ds,)
    deployer.list_rules.return_value = ()
    args_pull_ds = argparse.Namespace(
        engine_command="pull",
        target="datasets",
        force=True,
        out_dir=str(tmp_path / "custom"),
        out_manifest=str(tmp_path / "managed/index.yaml"),
        out_datasets_dir=str(tmp_path / "datasets"),
    )
    with pytest.raises(DatasetLoadError):
        controller.execute(args_pull_ds, json_output=True)

    # 2. Path traversal in remote rule name rejected
    evil_rule = RuleEnvelope(
        metadata=RuleMetadata(id="uuid-1", name="../evil_rule", description="evil"),
        logic="cond",
        deployment=BaseDeploymentConfig(enabled=True, alerting=True),
        runbook=Runbook(),
    )
    ds_port.list_datasets.return_value = ()
    deployer.list_rules.return_value = (evil_rule,)
    args_pull_custom = argparse.Namespace(
        engine_command="pull",
        target="custom",
        force=True,
        out_dir=str(tmp_path / "custom"),
        out_manifest=str(tmp_path / "managed/index.yaml"),
        out_datasets_dir=str(tmp_path / "datasets"),
    )
    with pytest.raises(RuleLoadError):
        controller.execute(args_pull_custom, json_output=True)

    # 3. pull --target all pulls datasets when capabilities.datasets is True and emits success: True
    good_ds = DatasetEnvelope(
        metadata=DatasetMetadata(
            name="trusted_scanners",
            description="Trusted scanners",
            owners=("team-a",),
            tags=("net",),
            references=("https://example.com",),
        ),
        values=("10.1.1.1",),
    )
    good_rule = RuleEnvelope(
        metadata=RuleMetadata(
            id="11111111-1111-1111-1111-111111111111",
            name="valid_pulled_rule",
            description="Valid rule",
            owners=("team-a",),
            mitre={"execution": ("T1059",)},
            tags=("cloud",),
            references=("https://example.com",),
        ),
        logic="cond",
        deployment=BaseDeploymentConfig(enabled=True, alerting=True, run_frequency="live"),
        runbook=Runbook(context="c", triage="t", response="r"),
    )
    ds_port.list_datasets.return_value = (good_ds,)
    deployer.list_rules.return_value = (good_rule,)
    capsys.readouterr()
    args_pull_all = argparse.Namespace(
        engine_command="pull",
        target="all",
        force=True,
        out_dir=str(tmp_path / "custom"),
        out_manifest=str(tmp_path / "managed/index.yaml"),
        out_datasets_dir=str(tmp_path / "datasets"),
    )
    rc = controller.execute(args_pull_all, json_output=True)
    assert rc == 0
    pull_payload = json.loads(capsys.readouterr().out)
    assert pull_payload["success"] is True
    assert pull_payload["datasets"]["count"] == 1
    assert pull_payload["custom"]["count"] == 1
    assert (tmp_path / "datasets" / "trusted_scanners.yaml").is_file()


def test_underscore_parent_workspace_and_uniqueness_and_mitre_version_parsing(
    tmp_path: Path,
) -> None:
    from graft.cli.engine_controller import _iter_custom_yaml_files
    from graft.core.models.rule import BaseDeploymentConfig, RuleEnvelope, RuleMetadata, Runbook
    from graft.core.validation.mitre_validator import (
        _parse_version_tuple,
        resolve_upstream_stix_release,
    )
    from graft.core.validation.uniqueness_validator import RuleUniquenessValidator

    # H6: Workspace under underscore directory (e.g. /tmp/_work/...) must not hide rules
    work_root = tmp_path / "_work" / "rulesets" / "siem_alpha" / "custom"
    work_root.mkdir(parents=True)
    sample_file = work_root / "active_rule.yaml"
    sample_file.write_text("metadata: {}\n", encoding="utf-8")
    discovered = _iter_custom_yaml_files(work_root)
    assert sample_file in discovered

    # M1: Version validation & tuple parsing
    with pytest.raises(ValueError, match="Invalid MITRE ATT&CK version"):
        resolve_upstream_stix_release(version="../../evil")
    assert _parse_version_tuple("19.2-rc1") == (19, 2)
    assert _parse_version_tuple("20.0") == (20,)

    # M3: Case-insensitive UUID collision & same-path non-self-conflict
    uv = RuleUniquenessValidator()
    r_lower = RuleEnvelope(
        metadata=RuleMetadata(
            id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            name="rule_one",
            description="desc",
        ),
        logic="cond",
        deployment=BaseDeploymentConfig(),
        runbook=Runbook(),
    )
    r_upper = RuleEnvelope(
        metadata=RuleMetadata(
            id="AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
            name="rule_two",
            description="desc",
        ),
        logic="cond",
        deployment=BaseDeploymentConfig(),
        runbook=Runbook(),
    )
    path_a = tmp_path / "rule_one.yaml"
    path_b = tmp_path / "rule_two.yaml"
    assert uv.add_and_validate(r_lower, engine="siem_alpha", path=path_a) == []
    # Re-validating identical resolved file must not self-conflict
    assert uv.add_and_validate(r_lower, engine="siem_alpha", path=path_a.resolve()) == []
    # Uppercase UUID on a different file must be caught
    violations = uv.add_and_validate(r_upper, engine="siem_alpha", path=path_b)
    assert any(v.violation_type == "id" for v in violations)


def test_engine_registry_manifest_mismatch_and_markdown_pipe_escaping(tmp_path: Path) -> None:
    from graft.core.catalog import CatalogEntry, export_catalog_markdown
    from graft.core.engine_registry import EngineManifestLoadError

    eng_dir = tmp_path / "wrong_dir_name"
    eng_dir.mkdir(parents=True)
    (eng_dir / "engine.yaml").write_text(
        """name: mismatched_name
display_name: Mismatched
description: Mismatched engine
adapter_class: mock:Adapter
capabilities:
  custom_rules: true
environments:
  - production
env_vars:
  required: []
  optional: []
""",
        encoding="utf-8",
    )
    with pytest.raises(EngineManifestLoadError, match="must match directory name"):
        EngineRegistry(engines_dir=tmp_path, strict=True)

    entry = CatalogEntry(
        id="id-1",
        name="rule_name",
        engine="siem_alpha",
        rule_type="custom",
        status="enabled",
        description="desc",
        mitre_attack=("TA0002:T1059",),
        tags=(),
        author="Alice | Security\nTeam",
        owners=("Owner | One",),
        owner_count=1,
        created_at="2026-01-01",
        last_modified_at="2026-01-02",
        review_count=1,
        contributor_count=1,
    )
    md = export_catalog_markdown([entry])
    assert r"Alice \| Security Team" in md
    assert r"Owner \| One" in md
