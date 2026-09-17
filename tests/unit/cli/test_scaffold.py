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

    scaffold_engine("sentinel", project_root=tmp_path)

    # 1. Engine code in src/graft/engines/sentinel
    engine_dir = tmp_path / "src" / "graft" / "engines" / "sentinel"
    assert (engine_dir / "__init__.py").exists()
    assert (engine_dir / "config.py").exists()
    assert (engine_dir / "compiler.py").exists()
    assert (engine_dir / "deployer.py").exists()
    assert (engine_dir / "managed.py").exists()

    # 2. Schema in schemas/sentinel_custom.schema.json
    schema_file = tmp_path / "schemas" / "sentinel_custom.schema.json"
    assert schema_file.exists()

    # 3. Rules directories and managed manifest
    rules_dir = tmp_path / "rules" / "sentinel" / "custom"
    assert rules_dir.is_dir()
    managed_file = tmp_path / "rules" / "sentinel" / "managed.yaml"
    assert managed_file.exists()

    # 4. CLI router in src/graft/cli/engines/sentinel.py
    cli_file = tmp_path / "src" / "graft" / "cli" / "engines" / "sentinel.py"
    assert cli_file.exists()

    # 5. Tests skeleton in tests/engines/sentinel/test_compiler.py
    test_file = tmp_path / "tests" / "engines" / "sentinel" / "test_compiler.py"
    assert test_file.exists()

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
