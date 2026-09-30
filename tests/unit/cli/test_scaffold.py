from pathlib import Path

import pytest

from graft.cli.scaffold import (
    ScaffoldError,
    scaffold_engine,
    scaffold_rule,
)
from graft.core.loader import load_rule_from_yaml


def test_scaffold_engine_creates_structure_and_files(tmp_path: Path) -> None:
    env_example = tmp_path / ".env.example"
    env_example.write_text("# Base .env.example\n", encoding="utf-8")

    from graft.core.engine_registry import EngineRegistry

    scaffold_engine("sentinel", project_root=tmp_path)

    # 1. Encapsulated engine package in src/graft/engines/sentinel
    engine_dir = tmp_path / "src" / "graft" / "engines" / "sentinel"
    assert (engine_dir / "__init__.py").exists()
    assert (engine_dir / "engine.yaml").exists()
    assert (engine_dir / "adapter.py").exists()
    assert (engine_dir / "config.py").exists()
    assert (engine_dir / "compiler.py").exists()
    assert (engine_dir / "deployer.py").exists()
    assert (engine_dir / "README.md").exists()

    # 2. Co-located schemas in src/graft/engines/sentinel/schemas/
    custom_schema_file = engine_dir / "schemas" / "custom.schema.json"
    managed_schema_file = engine_dir / "schemas" / "managed.schema.json"
    assert custom_schema_file.exists()
    assert managed_schema_file.exists()

    # 3. Rulesets directories (custom/, managed/, _archived/) & initial example rule
    rules_dir = tmp_path / "rulesets" / "sentinel" / "custom"
    assert rules_dir.is_dir()
    assert (tmp_path / "rulesets" / "sentinel" / "managed").is_dir()
    example_rule = rules_dir / "sentinel_example_rule.yaml"
    assert example_rule.is_file()
    example_envelope = load_rule_from_yaml(example_rule, schema_name="base_custom")
    assert example_envelope.metadata.name == "sentinel_example_rule"
    assert "$e.metadata.event_type" not in example_envelope.logic
    assert (tmp_path / "rulesets" / "sentinel" / "_archived").is_dir()

    # 4. Engine tests in tests/engines/sentinel/
    tests_engine_dir = tmp_path / "tests" / "engines" / "sentinel"
    assert (tests_engine_dir / "test_compiler.py").exists()
    assert (tests_engine_dir / "test_adapter.py").exists()

    # 5. Manifest validates and is discoverable via EngineRegistry
    registry = EngineRegistry(engines_dir=tmp_path / "src" / "graft" / "engines")
    manifest = registry.get("sentinel")
    assert manifest.name == "sentinel"
    assert manifest.display_name == "Sentinel"
    assert manifest.capabilities.custom_rules is True

    # 6. .env.example updated with engine section
    assert "# ENGINE: SENTINEL" in env_example.read_text(encoding="utf-8")

    # 7. Generated adapter implements status/ID hooks and deployer wires logging
    adapter_code = (engine_dir / "adapter.py").read_text(encoding="utf-8")
    assert "from graft.core.models.managed import ManagedState" in adapter_code
    assert "def resolve_deployment_status(" in adapter_code
    assert "managed_state: ManagedState | None = None" in adapter_code
    assert "def has_managed_rule_id(" in adapter_code
    deployer_code = (engine_dir / "deployer.py").read_text(encoding="utf-8")
    assert 'logging.getLogger("graft.sentinel.deployer")' in deployer_code
    assert "logger.debug(" in deployer_code
    test_adapter_code = (tests_engine_dir / "test_adapter.py").read_text(encoding="utf-8")
    assert "resolve_deployment_status" in test_adapter_code
    assert "has_managed_rule_id" in test_adapter_code


def test_scaffold_engine_invalid_name(tmp_path: Path) -> None:
    with pytest.raises(ScaffoldError, match="Invalid engine name"):
        scaffold_engine("Invalid-Engine!", project_root=tmp_path)


def test_scaffold_engine_already_exists(tmp_path: Path) -> None:
    scaffold_engine("crowdstrike", project_root=tmp_path)
    with pytest.raises(ScaffoldError, match="already exists"):
        scaffold_engine("crowdstrike", project_root=tmp_path)


def test_scaffold_rule_success(tmp_path: Path) -> None:
    from graft.engines.secops.compiler import synthesize_yaral_rule

    rule_path = scaffold_rule("secops", "suspicious_powershell_execution", project_root=tmp_path)

    assert rule_path.exists()
    assert rule_path.name == "suspicious_powershell_execution.yaml"

    # Verify that the generated rule loads cleanly and validates against the schema
    envelope = load_rule_from_yaml(rule_path, schema_name="secops_custom")
    assert envelope.metadata.name == "suspicious_powershell_execution"
    assert envelope.metadata.id is not None
    assert len(envelope.metadata.owners) >= 1
    assert len(envelope.metadata.references) >= 1
    assert not envelope.logic.strip().startswith("rule ")
    assert envelope.deployment.enabled is False
    assert len(envelope.tests) >= 1

    # Synthesizing YARA-L must produce exactly one rule block (not double-wrapped)
    synth_text, _ = synthesize_yaral_rule(envelope)
    assert synth_text.count("rule suspicious_powershell_execution {") == 1


def test_scaffold_rule_invalid_name(tmp_path: Path) -> None:
    with pytest.raises(ScaffoldError, match="Invalid rule name"):
        scaffold_rule("secops", "Invalid Rule Name!", project_root=tmp_path)


def test_scaffold_rule_custom_destination(tmp_path: Path) -> None:
    custom_out = tmp_path / "custom_dir" / "my_rule.yaml"
    rule_path = scaffold_rule("secops", "custom_rule", project_root=tmp_path, out_path=custom_out)
    assert rule_path == custom_out
    assert custom_out.exists()


def test_scaffold_rule_custom_destination_string(tmp_path: Path) -> None:
    custom_out_str = str(tmp_path / "str_dir" / "my_str_rule.yaml")
    rule_path = scaffold_rule(
        "secops", "custom_rule_str", project_root=tmp_path, out_path=custom_out_str
    )
    assert str(rule_path) == custom_out_str
    assert rule_path.exists()


def test_scaffold_managed_rule_requires_managed_id(tmp_path: Path) -> None:
    with pytest.raises(ScaffoldError, match="requires a non-empty managed rule ID"):
        scaffold_rule(
            "secops",
            "gcti_active_breach_host_indicators",
            project_root=tmp_path,
            managed=True,
        )
    with pytest.raises(ScaffoldError, match="requires a non-empty managed rule ID"):
        scaffold_rule(
            "secops",
            "gcti_active_breach_host_indicators",
            project_root=tmp_path,
            managed=True,
            managed_id="   ",
        )


def test_scaffold_managed_rule_with_explicit_id(tmp_path: Path) -> None:
    rule_path = scaffold_rule(
        "secops",
        "gcti_active_breach_network_indicators",
        project_root=tmp_path,
        managed=True,
        managed_id="433faf9e-4d51-f284-c35b-009528ecff05",
    )
    assert rule_path == (
        tmp_path / "rulesets" / "secops" / "managed" / "gcti_active_breach_network_indicators.yaml"
    )
    envelope = load_rule_from_yaml(rule_path)
    assert envelope.is_managed is True
    assert envelope.rule_type == "managed"
    assert envelope.metadata.id is not None
    assert envelope.managed is not None
    assert envelope.managed.id == "433faf9e-4d51-f284-c35b-009528ecff05"
    assert envelope.tests == ()


def test_scaffold_rule_rejects_reserved_index_name(tmp_path: Path) -> None:
    with pytest.raises(ScaffoldError, match="reserved"):
        scaffold_rule("secops", "index", project_root=tmp_path)
    with pytest.raises(ScaffoldError, match="reserved"):
        scaffold_rule(
            "secops",
            "index",
            project_root=tmp_path,
            managed=True,
            managed_id="433faf9e-4d51-f284-c35b-009528ecff05",
        )
