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
