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

    rules_custom_dir = root / "rules" / name / "custom"
    schemas_dir = root / "schemas"
    cli_engines_dir = root / "src" / "graft" / "cli" / "engines"
    tests_engine_dir = root / "tests" / "engines" / name

    engine_dir.mkdir(parents=True, exist_ok=True)
    rules_custom_dir.mkdir(parents=True, exist_ok=True)
    schemas_dir.mkdir(parents=True, exist_ok=True)
    cli_engines_dir.mkdir(parents=True, exist_ok=True)
    tests_engine_dir.mkdir(parents=True, exist_ok=True)

    class_prefix = "".join(part.capitalize() for part in name.split("_"))
    created_files: dict[str, Path] = {}

    # 1. engine package files
    init_py = engine_dir / "__init__.py"
    init_py.write_text(f'"""{class_prefix} engine implementation."""\n', encoding="utf-8")
    created_files["init"] = init_py

    config_py = engine_dir / "config.py"
    config_py.write_text(
        f"""from dataclasses import dataclass
from typing import Self


@dataclass(frozen=True)
class {class_prefix}Config:
    tenant_id: str

    @classmethod
    def from_env(cls) -> Self:
        return cls(tenant_id="default")
""",
        encoding="utf-8",
    )
    created_files["config"] = config_py

    compiler_py = engine_dir / "compiler.py"
    compiler_py.write_text(
        f"""from graft.core.models.compiler import CompilationResult
from graft.core.ports.compiler import RuleCompilerPort


class {class_prefix}CompilerAdapter(RuleCompilerPort):
    def verify_syntax(self, rule_text: str) -> CompilationResult:
        return CompilationResult(success=True)
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

    managed_py = engine_dir / "managed.py"
    managed_py.write_text(
        f"""from graft.core.models.managed import ManagedExclusion, ManagedState
from graft.core.ports.managed import ManagedEnginePort


class {class_prefix}ManagedAdapter(ManagedEnginePort):
    def fetch_managed_state(self) -> ManagedState:
        return ManagedState(rulesets=(), exclusions=())

    def apply_managed_state(self, target_state: ManagedState) -> None:
        pass

    def set_ruleset_deployment(
        self,
        ruleset_id: str,
        deployment_type: str,
        enabled: bool,
        alerting: bool,
        category: str | None = None,
    ) -> None:
        pass

    def create_exclusion(self, exclusion: ManagedExclusion) -> str:
        return exclusion.id

    def update_exclusion(self, exclusion: ManagedExclusion) -> None:
        pass

    def delete_exclusion(self, exclusion_id: str) -> None:
        pass
""",
        encoding="utf-8",
    )
    created_files["managed"] = managed_py

    # 2. Schema
    schema_file = schemas_dir / f"{name}_custom.schema.json"
    schema_content = f"""{{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "{name}_custom.schema.json",
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

    # 3. Rules
    managed_manifest = root / "rules" / name / "managed.yaml"
    managed_manifest.write_text("rulesets: []\nexclusions: []\n", encoding="utf-8")
    created_files["managed_yaml"] = managed_manifest

    # 4. CLI Router
    cli_file = cli_engines_dir / f"{name}.py"
    cli_content = f'''from __future__ import annotations

import argparse
import sys


def register_engine(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("{name}", help="{class_prefix} engine commands")
    parser.set_defaults(engine_handler=handle_{name}_command)
    cmd_subparsers = parser.add_subparsers(dest="engine_command", required=True)

    # new
    new_p = cmd_subparsers.add_parser("new", help="Bootstrap a new {name} rule")
    new_p.add_argument("rule_name", help="Name of the new rule (lowercase slug)")
    new_p.add_argument("--out", help="Custom output path for the rule file")

    # verify
    verify_p = cmd_subparsers.add_parser("verify", help="Verify rule syntax and schema")
    verify_p.add_argument("paths", nargs="*", help="Rule paths to verify")
    verify_p.add_argument("--env", choices=["staging", "production"], default="staging")

    # diff
    diff_p = cmd_subparsers.add_parser("diff", help="Diff local state against tenant")
    diff_p.add_argument("--env", choices=["staging", "production"], default="production")

    # apply
    apply_p = cmd_subparsers.add_parser("apply", help="Apply local state to tenant")
    apply_p.add_argument("--env", choices=["staging", "production"], default="production")


def handle_{name}_command(args: argparse.Namespace, json_output: bool = False) -> int:
    cmd = getattr(args, "engine_command", "")
    if cmd == "new":
        from graft.cli.scaffold import scaffold_rule

        rule_path = scaffold_rule("{name}", args.rule_name, out_path=getattr(args, "out", None))
        sys.stdout.write(f"Scaffolded {name} rule template at: {{rule_path}}\\n")
        return 0
    sys.stdout.write(f"{name} {{cmd}} executed cleanly.\\n")
    return 0
'''
    cli_file.write_text(cli_content, encoding="utf-8")
    created_files["cli"] = cli_file

    # 5. Tests
    test_file = tests_engine_dir / "test_compiler.py"
    test_content = f"""from graft.engines.{name}.compiler import {class_prefix}CompilerAdapter


def test_{name}_compiler_stub() -> None:
    compiler = {class_prefix}CompilerAdapter()
    res = compiler.verify_syntax("test")
    assert res.success is True
"""
    test_file.write_text(test_content, encoding="utf-8")
    created_files["test"] = test_file

    return created_files


def scaffold_rule(
    engine: str,
    rule_name: str,
    project_root: Path | None = None,
    out_path: Path | None = None,
) -> Path:
    _validate_identifier(rule_name, "rule")
    _validate_identifier(engine, "engine")
    root = project_root or Path.cwd()

    dest = out_path or (root / "rules" / engine / "custom" / f"{rule_name}.yaml")
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
    if (schema_dir / f"{engine}_custom.schema.json").exists():
        validator = SchemaValidator(schemas_dir=schema_dir)
        errors = validator.validate(doc, schema_name=f"{engine}_custom")
        if errors:
            err_msg = "; ".join(f"{e.path}: {e.message}" for e in errors)
            raise ScaffoldError(f"Scaffolded rule template failed schema validation: {err_msg}")

    dumped = yaml.safe_dump(doc, sort_keys=False, indent=2)
    dest.write_text(dumped, encoding="utf-8")
    return dest
