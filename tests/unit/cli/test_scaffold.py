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

    # 2. Co-located schema in src/graft/engines/sentinel/schemas/rule.schema.json
    schema_file = engine_dir / "schemas" / "rule.schema.json"
    assert schema_file.exists()

    # 3. Rules directory
    rules_dir = tmp_path / "rules" / "sentinel" / "custom"
    assert rules_dir.is_dir()

    # 4. In-tree tests in src/graft/engines/sentinel/tests/
    assert (engine_dir / "tests" / "test_compiler.py").exists()
    assert (engine_dir / "tests" / "test_adapter.py").exists()

    # 5. Manifest validates and is discoverable via EngineRegistry
    registry = EngineRegistry(engines_dir=tmp_path / "src" / "graft" / "engines")
    manifest = registry.get("sentinel")
    assert manifest.name == "sentinel"
    assert manifest.display_name == "Sentinel"
    assert manifest.capabilities.custom_rules is True

    # 6. .env.example updated with engine section
    assert "# ENGINE: SENTINEL" in env_example.read_text(encoding="utf-8")


def test_scaffold_engine_invalid_name(tmp_path: Path) -> None:
    with pytest.raises(ScaffoldError, match="Invalid engine name"):
        scaffold_engine("Invalid-Engine!", project_root=tmp_path)


def test_scaffold_engine_already_exists(tmp_path: Path) -> None:
    scaffold_engine("crowdstrike", project_root=tmp_path)
    with pytest.raises(ScaffoldError, match="already exists"):
        scaffold_engine("crowdstrike", project_root=tmp_path)


def test_scaffold_rule_success(tmp_path: Path) -> None:
    rule_path = scaffold_rule("secops", "suspicious_powershell_execution", project_root=tmp_path)

    assert rule_path.exists()
    assert rule_path.name == "suspicious_powershell_execution.yaml"

    # Verify that the generated rule loads cleanly and validates against the schema
    envelope = load_rule_from_yaml(rule_path, schema_name="secops_custom")
    assert envelope.metadata.name == "suspicious_powershell_execution"
    assert envelope.metadata.id is not None
    assert envelope.metadata.status == "testing"
    assert envelope.deployment.enabled is False
    assert len(envelope.tests) >= 1


def test_scaffold_rule_invalid_name(tmp_path: Path) -> None:
    with pytest.raises(ScaffoldError, match="Invalid rule name"):
        scaffold_rule("secops", "Invalid Rule Name!", project_root=tmp_path)


def test_scaffold_rule_custom_destination(tmp_path: Path) -> None:
    custom_out = tmp_path / "custom_dir" / "my_rule.yaml"
    rule_path = scaffold_rule("secops", "custom_rule", project_root=tmp_path, out_path=custom_out)
    assert rule_path == custom_out
    assert custom_out.exists()
