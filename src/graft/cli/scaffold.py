import re
import uuid
from pathlib import Path

import yaml

from graft.core.validation.schema_validator import SchemaValidator

IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)*$")
MAX_IDENTIFIER_LEN = 64


class ScaffoldError(Exception):
    pass


def _validate_identifier(name: str, kind: str) -> None:
    if not (1 <= len(name) <= MAX_IDENTIFIER_LEN) or not IDENTIFIER_PATTERN.match(name):
        raise ScaffoldError(
            f"Invalid {kind} name '{name}'. Must be 1..{MAX_IDENTIFIER_LEN} chars matching "
            f"{IDENTIFIER_PATTERN.pattern} (lowercase alphanumeric and single underscores, "
            "never starting or ending with underscores)"
        )


def scaffold_engine(name: str, project_root: Path | None = None) -> dict[str, Path]:
    _validate_identifier(name, "engine")
    root = project_root or Path.cwd()

    engine_dir = root / "src" / "graft" / "engines" / name
    if engine_dir.exists():
        raise ScaffoldError(f"Engine '{name}' already exists at {engine_dir}")

    schemas_dir = engine_dir / "schemas"
    tests_engine_dir = root / "tests" / "engines" / name
    rules_custom_dir = root / "rulesets" / name / "custom"
    rules_managed_dir = root / "rulesets" / name / "managed"
    rules_archived_dir = root / "rulesets" / name / "_archived"

    engine_dir.mkdir(parents=True, exist_ok=True)
    schemas_dir.mkdir(parents=True, exist_ok=True)
    tests_engine_dir.mkdir(parents=True, exist_ok=True)
    rules_custom_dir.mkdir(parents=True, exist_ok=True)
    rules_managed_dir.mkdir(parents=True, exist_ok=True)
    rules_archived_dir.mkdir(parents=True, exist_ok=True)

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

from graft.core.models.managed import ManagedState
from graft.core.models.rule import RuleEnvelope
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

    def has_managed_rule_id(self, managed_id: str, state: ManagedState) -> bool:
        return any(rs.id == managed_id for cat in state.categories for rs in cat.rulesets)

    def resolve_deployment_status(
        self,
        rule: RuleEnvelope,
        managed_state: ManagedState | None = None,
    ) -> str:
        if rule.is_managed and rule.managed is not None:
            if managed_state is None:
                return "disabled"
            for cat in managed_state.categories:
                for rs in cat.rulesets:
                    if rs.id == rule.managed.id:
                        if any(d.enabled and d.alerting for d in rs.deployments):
                            return "enabled"
                        if any(d.enabled for d in rs.deployments):
                            return "silent"
                        return "disabled"
            return "disabled"
        if not rule.deployment.enabled:
            return "disabled"
        if not rule.deployment.alerting:
            return "silent"
        return "enabled"
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
        f"""import logging

from graft.core.models.rule import RuleEnvelope
from graft.core.ports.deployer import RuleDeployerPort

logger = logging.getLogger("graft.{name}.deployer")


class {class_prefix}DeployerAdapter(RuleDeployerPort):
    def list_rules(self) -> tuple[RuleEnvelope, ...]:
        return ()

    def create_rule(self, rule: RuleEnvelope) -> str:
        logger.debug("Creating rule '%s' (%s)", rule.metadata.name, rule.metadata.id)
        return rule.metadata.id

    def update_rule(self, rule: RuleEnvelope) -> None:
        logger.debug("Updating rule '%s' (%s)", rule.metadata.name, rule.metadata.id)

    def delete_rule(self, rule_id: str) -> None:
        logger.debug("Deleting rule '%s'", rule_id)

    def set_rule_state(self, rule_id: str, enabled: bool, alerting: bool) -> None:
        logger.debug(
            "Setting rule '%s' state (enabled=%s, alerting=%s)",
            rule_id,
            enabled,
            alerting,
        )
""",
        encoding="utf-8",
    )
    created_files["deployer"] = deployer_py

    # 4. Co-located Schemas in src/graft/engines/{name}/schemas/
    schema_file = schemas_dir / "custom.schema.json"
    schema_content = f"""{{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "{name}_custom.schema.json",
  "title": "{class_prefix} Custom Rule Envelope Schema",
  "type": "object",
  "allOf": [
    {{
      "$ref": "base_custom.schema.json"
    }},
    {{
      "type": "object",
      "properties": {{
        "deployment": {{
          "type": "object",
          "required": [
            "enabled",
            "alerting",
            "run_frequency"
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

    managed_schema_file = schemas_dir / "managed.schema.json"
    managed_schema_content = f"""{{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "{name}_managed.schema.json",
  "title": "{class_prefix} Managed Content Manifest Schema (managed/index.yaml)",
  "type": "object",
  "required": [
    "categories",
    "exclusions"
  ],
  "properties": {{
    "categories": {{
      "type": "array",
      "items": {{
        "type": "object",
        "required": [
          "id",
          "name",
          "rulesets"
        ],
        "properties": {{
          "id": {{
            "type": "string",
            "minLength": 1
          }},
          "name": {{
            "type": "string",
            "minLength": 1
          }},
          "rulesets": {{
            "type": "array",
            "items": {{
              "type": "object",
              "required": [
                "id",
                "name"
              ],
              "properties": {{
                "id": {{
                  "type": "string",
                  "minLength": 1
                }},
                "name": {{
                  "type": "string",
                  "minLength": 1
                }}
              }}
            }}
          }}
        }},
        "additionalProperties": false
      }}
    }},
    "exclusions": {{
      "type": "array",
      "items": {{
        "type": "object",
        "required": [
          "id",
          "description",
          "expression"
        ],
        "properties": {{
          "id": {{
            "type": "string",
            "minLength": 1
          }},
          "description": {{
            "type": "string",
            "minLength": 1
          }},
          "expression": {{
            "type": "string",
            "minLength": 1
          }}
        }}
      }}
    }}
  }},
  "additionalProperties": false
}}
"""
    managed_schema_file.write_text(managed_schema_content, encoding="utf-8")
    created_files["managed_schema"] = managed_schema_file

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
    assert callable(adapter.resolve_deployment_status)
    assert callable(adapter.has_managed_rule_id)
""",
        encoding="utf-8",
    )
    created_files["test_adapter"] = test_adapter_file

    # 7. Initial example rule in rulesets/{name}/custom/{name}_example_rule.yaml
    example_rule_file = scaffold_rule(name, f"{name}_example_rule", project_root=root)
    created_files["example_rule"] = example_rule_file

    # 8. Append engine config section to .env.example and .env if present
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
    managed: bool = False,
    managed_id: str | None = None,
) -> Path:
    _validate_identifier(rule_name, "rule")
    if rule_name == "index":
        raise ScaffoldError("Invalid rule name 'index'. 'index' is reserved for managed/index.yaml")
    _validate_identifier(engine, "engine")
    if managed_id is not None:
        managed = True
    root = Path(project_root) if project_root else Path.cwd()

    subdir = "managed" if managed else "custom"
    dest = (
        Path(out_path) if out_path else (root / "rulesets" / engine / subdir / f"{rule_name}.yaml")
    )
    if dest.stem == "index":
        raise ScaffoldError(
            "Invalid rule filename 'index'. 'index' is reserved for managed/index.yaml"
        )
    _validate_identifier(dest.stem, "rule filename")
    if dest.exists():
        raise ScaffoldError(f"Rule file already exists at {dest}")

    if managed:
        if not managed_id or not managed_id.strip():
            raise ScaffoldError(
                "Scaffolding a managed rule requires a non-empty managed rule ID (--managed <id>)"
            )
        dest.parent.mkdir(parents=True, exist_ok=True)
        rule_uuid = str(uuid.uuid4())
        doc: dict[str, object] = {
            "metadata": {
                "id": rule_uuid,
                "name": rule_name,
                "description": f"Registered managed rule for {rule_name.replace('_', ' ')}",
                "owners": ["Detection Engineering <detection@company.com>"],
                "mitre": {
                    "execution": ["T1059.001"],
                },
                "tags": [engine, "managed"],
                "references": ["https://attack.mitre.org/techniques/T1059/001/"],
            },
            "managed": {
                "id": managed_id.strip(),
            },
            "runbook": {
                "context": "Context and background regarding this vendor-managed detection.",
                "triage": "1. Verify principal user and host.\n2. Examine correlated telemetry.",
                "response": "1. Isolate compromised entity if warranted.\n2. Revoke active tokens.",
            },
            "tests": [],
        }
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        rule_uuid = str(uuid.uuid4())
        default_logic = (
            """events:
  $e.metadata.event_type = "USER_LOGIN"
condition:
  $e"""
            if engine == "secops"
            else f'events | where rule_name == "{rule_name}" and event_type == "USER_LOGIN"'
        )

        doc = {
            "metadata": {
                "id": rule_uuid,
                "name": rule_name,
                "description": f"Detection rule for {rule_name.replace('_', ' ')}",
                "owners": ["Detection Engineering <detection@company.com>"],
                "mitre": {
                    "execution": ["T1059.001"],
                },
                "tags": [engine, "custom"],
                "references": ["https://attack.mitre.org/techniques/T1059/001/"],
            },
            "logic": default_logic,
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
    schema_dir = root / "src" / "graft" / "core" / "schemas"
    if not schema_dir.is_dir():
        schema_dir = root / "schemas"
    engines_dir = root / "src" / "graft" / "engines"
    try:
        validator = SchemaValidator(
            schemas_dir=schema_dir if schema_dir.is_dir() else None,
            engines_dir=engines_dir if engines_dir.is_dir() else None,
        )
        avail = validator.available_schemas()
        target_schema = None
        candidates = (
            ("base_managed",)
            if managed
            else (f"{engine}:custom", f"{engine}_custom", "base_custom")
        )
        for candidate in candidates:
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
