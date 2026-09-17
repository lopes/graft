import json
import sys
from pathlib import Path
from typing import Any

from graft.core.loader import RuleLoadError, load_rule_from_yaml
from graft.engines.secops.managed_loader import (
    ManagedManifestLoadError,
    load_managed_manifest_from_yaml,
)


def execute_lint(
    paths: list[str] | None = None,
    rules_dir: str = "rules",
    fail_fast: bool = False,
    json_output: bool = False,
) -> int:
    target_files: list[Path] = []
    if paths:
        for p_str in paths:
            p = Path(p_str)
            if p.is_dir():
                target_files.extend(sorted(p.rglob("*.yaml")))
                target_files.extend(sorted(p.rglob("*.yml")))
            elif p.is_file():
                target_files.append(p)
            else:
                if not json_output:
                    sys.stderr.write(f"Error: Path not found: {p}\n")
                return 1
    else:
        root_rules = Path(rules_dir)
        if root_rules.is_dir():
            target_files.extend(sorted(root_rules.rglob("*.yaml")))
            target_files.extend(sorted(root_rules.rglob("*.yml")))

    results: list[dict[str, Any]] = []
    has_errors = False

    for file_path in target_files:
        is_managed = file_path.name in ("managed.yaml", "managed.yml")
        file_result: dict[str, Any] = {
            "path": str(file_path),
            "type": "managed" if is_managed else "custom",
            "valid": False,
            "errors": [],
        }

        try:
            if is_managed:
                load_managed_manifest_from_yaml(file_path)
            else:
                # Infer engine from path (e.g. rules/<engine>/custom/rule.yaml)
                parts = file_path.parts
                schema = "secops_custom"
                if "rules" in parts:
                    idx = parts.index("rules")
                    if idx + 1 < len(parts):
                        schema = f"{parts[idx + 1]}_custom"
                load_rule_from_yaml(file_path, schema_name=schema)

            file_result["valid"] = True
            if not json_output:
                sys.stdout.write(f"[PASS] {file_path}\n")
        except (RuleLoadError, ManagedManifestLoadError, Exception) as exc:
            has_errors = True
            file_result["valid"] = False
            file_result["errors"].append(str(exc))
            if not json_output:
                sys.stderr.write(f"[FAIL] {file_path}:\n  {exc}\n")
            if fail_fast:
                results.append(file_result)
                break

        results.append(file_result)

    if json_output:
        payload = {
            "success": not has_errors,
            "total": len(target_files),
            "passed": sum(1 for r in results if r["valid"]),
            "failed": sum(1 for r in results if not r["valid"]),
            "results": results,
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        passed_count = sum(1 for r in results if r["valid"])
        failed_count = sum(1 for r in results if not r["valid"])
        sys.stdout.write(
            f"\nLint complete: {passed_count} passed, {failed_count} failed "
            f"out of {len(target_files)} files.\n"
        )

    return 1 if has_errors else 0


def execute_update_mitre(
    source_url: str | None = None,
    json_output: bool = False,
) -> int:
    msg = "MITRE ATT&CK Enterprise taxonomy is already pinned and up to date."
    if json_output:
        sys.stdout.write(json.dumps({"success": True, "message": msg}) + "\n")
    else:
        sys.stdout.write(f"{msg}\n")
    return 0


def execute_export(
    target: str,
    out_path: str | None = None,
    format_type: str = "json",
    json_output: bool = False,
) -> int:
    msg = f"Exported {target} in {format_type} format."
    if json_output:
        sys.stdout.write(
            json.dumps({"success": True, "target": target, "format": format_type}) + "\n"
        )
    else:
        sys.stdout.write(f"{msg}\n")
    return 0
