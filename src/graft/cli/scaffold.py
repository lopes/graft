import re
import uuid
from pathlib import Path

import yaml

from graft.core.validation.schema_validator import SchemaValidator

IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9_]+$")


class ScaffoldError(Exception):
    pass


def _validate_identifier(name: str, kind: str) -> None:
    if not IDENTIFIER_PATTERN.match(name):
        raise ScaffoldError(f"Invalid {kind} name '{name}'. Must match lowercase slug ^[a-z0-9_]+$")


def scaffold_engine(name: str, project_root: Path | None = None) -> dict[str, Path]:
    _validate_identifier(name, "engine")
    root = project_root or Path.cwd()

    engine_dir = root / "src" / "graft" / "engines" / name
    if engine_dir.exists():
        raise ScaffoldError(f"Engine '{name}' already exists at {engine_dir}")

    schemas_dir = engine_dir / "schemas"
    tests_engine_dir = engine_dir / "tests"
    rules_custom_dir = root / "rules" / name / "custom"

    engine_dir.mkdir(parents=True, exist_ok=True)
    schemas_dir.mkdir(parents=True, exist_ok=True)
    tests_engine_dir.mkdir(parents=True, exist_ok=True)
    rules_custom_dir.mkdir(parents=True, exist_ok=True)

    class_prefix = "".join(part.capitalize() for part in name.split("_"))
    created_files: dict[str, Path] = {}

    # 1. engine package files
    init_py = engine_dir / "__init__.py"
    init_py.write_text(f'"""{class_prefix} engine implementation."""\n', encoding="utf-8")
    created_files["init"] = init_py

    # 2. engine manifest (engine.yaml)
    manifest_file = engine_dir / "engine.yaml"
    manifest_content = f"""name: {name}
display_name: {class_prefix}
description: {class_prefix} Detection Engine Adapter
adapter_class: graft.engines.{name}.adapter:{class_prefix}Adapter

capabilities:
  custom_rules: true
  syntax_verification: true
  managed_rules: false
  replay_testing: false

environments:
  - staging
  - production

env_vars:
  required:
    - GRAFT_{name.upper()}_API_KEY
  optional: []
"""
    manifest_file.write_text(manifest_content, encoding="utf-8")
    created_files["manifest"] = manifest_file

    # 3. adapter implementation
    adapter_py = engine_dir / "adapter.py"
    adapter_content = f"""from __future__ import annotations

from graft.core.ports.compiler import RuleCompilerPort
from graft.core.ports.deployer import RuleDeployerPort
from graft.core.ports.engine import EngineAdapter
from graft.core.ports.managed import ManagedEnginePort
from graft.core.ports.replay import ReplayHarnessPort
from graft.engines.{name}.compiler import {class_prefix}CompilerAdapter
from graft.engines.{name}.deployer import {class_prefix}DeployerAdapter


class {class_prefix}Adapter(EngineAdapter):
    def __init__(self, env: str = "production") -> None:
        self.env = env
        self._compiler = {class_prefix}CompilerAdapter()
        self._deployer = {class_prefix}DeployerAdapter()

    def get_compiler(self) -> RuleCompilerPort | None:
        return self._compiler

    def get_deployer(self) -> RuleDeployerPort | None:
        return self._deployer

    def get_managed(self) -> ManagedEnginePort | None:
        return None

    def get_replay(self) -> ReplayHarnessPort | None:
        return None
"""
    adapter_py.write_text(adapter_content, encoding="utf-8")
    created_files["adapter"] = adapter_py

    config_py = engine_dir / "config.py"
    config_py.write_text(
        f"""from dataclasses import dataclass
from typing import Self


@dataclass(frozen=True)
class {class_prefix}Config:
    api_key: str = "default"

    @classmethod
    def from_env(cls) -> Self:
        return cls()
""",
        encoding="utf-8",
    )
    created_files["config"] = config_py

    compiler_py = engine_dir / "compiler.py"
    compiler_py.write_text(
        f"""from graft.core.models.compiler import CompilationResult
from graft.core.models.rule import RuleEnvelope
from graft.core.ports.compiler import RuleCompilerPort


class {class_prefix}CompilerAdapter(RuleCompilerPort):
    def verify_syntax(self, rule_text: str) -> CompilationResult:
        return CompilationResult(success=True)

    def verify_rule(self, rule: RuleEnvelope) -> CompilationResult:
        return self.verify_syntax(rule.logic)
""",
        encoding="utf-8",
    )
    created_files["compiler"] = compiler_py

    deployer_py = engine_dir / "deployer.py"
    deployer_py.write_text(
        f"""from graft.core.models.rule import RuleEnvelope
from graft.core.ports.deployer import RuleDeployerPort


class {class_prefix}DeployerAdapter(RuleDeployerPort):
    def list_rules(self) -> tuple[RuleEnvelope, ...]:
        return ()

    def create_rule(self, rule: RuleEnvelope) -> str:
        return rule.metadata.id

    def update_rule(self, rule: RuleEnvelope) -> None:
        pass

    def delete_rule(self, rule_id: str) -> None:
        pass

    def set_rule_state(self, rule_id: str, enabled: bool, alerting: bool) -> None:
        pass
""",
        encoding="utf-8",
    )
    created_files["deployer"] = deployer_py

    # 4. Co-located Schema in src/graft/engines/{name}/schemas/rule.schema.json
    schema_file = schemas_dir / "rule.schema.json"
    schema_content = f"""{{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "{name}_rule.schema.json",
  "title": "{class_prefix} Custom Rule Envelope Schema",
  "type": "object",
  "allOf": [
    {{
      "$ref": "base_rule.schema.json"
    }},
    {{
      "type": "object",
      "properties": {{
        "deployment": {{
          "type": "object",
          "required": [
            "enabled",
            "alerting"
          ],
          "properties": {{
            "enabled": {{
              "type": "boolean"
            }},
            "alerting": {{
              "type": "boolean"
            }},
            "run_frequency": {{
              "type": "string",
              "enum": [
                "unspecified",
                "live",
                "hourly",
                "daily"
              ]
            }}
          }},
          "additionalProperties": false
        }}
      }}
    }}
  ]
}}
"""
    schema_file.write_text(schema_content, encoding="utf-8")
    created_files["schema"] = schema_file

    # 5. README documentation
    readme_file = engine_dir / "README.md"
    readme_file.write_text(
        f"""# {class_prefix} Engine Adapter

Detection Engine Adapter for {class_prefix}.

## Overview
Concrete adapter implementing the `EngineAdapter` protocol for {class_prefix}.

## Capabilities
- Custom rules: Supported
- Syntax verification: Supported
- Managed rules: Not supported
- Replay testing: Not supported
""",
        encoding="utf-8",
    )
    created_files["readme"] = readme_file

    # 6. In-tree Tests
    (tests_engine_dir / "__init__.py").write_text("", encoding="utf-8")
    test_compiler_file = tests_engine_dir / "test_compiler.py"
    test_compiler_file.write_text(
        f"""from graft.engines.{name}.compiler import {class_prefix}CompilerAdapter


def test_{name}_compiler_stub() -> None:
    compiler = {class_prefix}CompilerAdapter()
    res = compiler.verify_syntax("test")
    assert res.success is True
""",
        encoding="utf-8",
    )
    created_files["test_compiler"] = test_compiler_file

    test_adapter_file = tests_engine_dir / "test_adapter.py"
    test_adapter_file.write_text(
        f"""from graft.core.ports.engine import EngineAdapter
from graft.engines.{name}.adapter import {class_prefix}Adapter


def test_{name}_adapter_protocol_conformance() -> None:
    adapter = {class_prefix}Adapter()
    assert isinstance(adapter, EngineAdapter)
    assert adapter.get_compiler() is not None
    assert adapter.get_deployer() is not None
""",
        encoding="utf-8",
    )
    created_files["test_adapter"] = test_adapter_file

    # 7. Append engine config section to .env.example and .env if present
    section_tag = f"# ENGINE: {name.upper()}"
    section_stub = f"""

# ==============================================================================
# ENGINE: {name.upper()}
# ==============================================================================
# Configuration and credentials for {name}
# GRAFT_{name.upper()}_API_KEY=
"""
    for env_filename in (".env.example", ".env"):
        env_path = root / env_filename
        if env_path.exists():
            content = env_path.read_text(encoding="utf-8")
            if section_tag not in content:
                env_path.write_text(content.rstrip() + section_stub, encoding="utf-8")

    return created_files


def scaffold_rule(
    engine: str,
    rule_name: str,
    project_root: Path | None = None,
    out_path: Path | str | None = None,
) -> Path:
    _validate_identifier(rule_name, "rule")
    _validate_identifier(engine, "engine")
    root = Path(project_root) if project_root else Path.cwd()

    dest = (
        Path(out_path) if out_path else (root / "rules" / engine / "custom" / f"{rule_name}.yaml")
    )
    if dest.exists():
        raise ScaffoldError(f"Rule file already exists at {dest}")

    dest.parent.mkdir(parents=True, exist_ok=True)
    rule_uuid = str(uuid.uuid4())

    doc: dict[str, object] = {
        "metadata": {
            "id": rule_uuid,
            "name": rule_name,
            "description": f"Detection rule for {rule_name.replace('_', ' ')}",
            "status": "testing",
            "priority": "medium",
            "authors": ["Detection Engineering <detection@company.com>"],
            "mitre": {
                "execution": ["T1059.001"],
            },
            "tags": [engine, "custom"],
            "references": [],
        },
        "logic": f"""rule {rule_name} {{
  meta:
  events:
    $e.metadata.event_type = "USER_LOGIN"
  condition:
    $e
}}""",
        "deployment": {
            "enabled": False,
            "alerting": False,
            "run_frequency": "live",
        },
        "runbook": {
            "context": "Context and background regarding this detection.",
            "triage": "1. Verify principal user and host.\n2. Examine correlated telemetry.",
            "response": "1. Isolate compromised entity if warranted.\n2. Revoke active tokens.",
        },
        "tests": [
            {
                "id": "test_basic_detection",
                "description": "Verify rule detects single event",
                "events": [
                    {
                        "timestamp": "2026-09-17T12:00:00Z",
                        "payload": {"metadata": {"event_type": "USER_LOGIN"}},
                    }
                ],
                "expect": 1,
            }
        ],
    }

    # Validate against schema if schema is available
    schema_dir = root / "schemas"
    engines_dir = root / "src" / "graft" / "engines"
    try:
        validator = SchemaValidator(
            schemas_dir=schema_dir if schema_dir.is_dir() else None,
            engines_dir=engines_dir if engines_dir.is_dir() else None,
        )
        avail = validator.available_schemas()
        target_schema = None
        for candidate in (f"{engine}:rule", f"{engine}_rule", f"{engine}_custom"):
            if candidate in avail:
                target_schema = candidate
                break

        if target_schema:
            errors = validator.validate(doc, schema_name=target_schema)
            if errors:
                err_msg = "; ".join(f"{e.path}: {e.message}" for e in errors)
                raise ScaffoldError(f"Scaffolded rule template failed schema validation: {err_msg}")
    except (FileNotFoundError, KeyError):
        pass

    dumped = yaml.safe_dump(doc, sort_keys=False, indent=2)
    dest.write_text(dumped, encoding="utf-8")
    return dest
