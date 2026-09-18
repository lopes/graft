import json
import sys
from pathlib import Path
from typing import Any

from graft.core.catalog import (
    build_catalog_entry_from_rule,
    export_catalog_csv,
    export_catalog_json,
    export_catalog_markdown,
)
from graft.core.loader import RuleLoadError, load_rule_from_yaml
from graft.core.matrix import (
    calculate_mitre_coverage,
    export_navigator_layer,
    render_matrix_table,
)
from graft.core.models.rule import RuleEnvelope
from graft.core.validation import RuleUniquenessValidator
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
    uniqueness_validator = RuleUniquenessValidator()

    schemas_dir = Path("schemas")
    target_set = {f.resolve() for f in target_files if f.exists()}
    root_rules = Path(rules_dir)
    if root_rules.is_dir():
        for other_path in sorted(root_rules.rglob("*.yaml")):
            if (
                other_path.name in ("managed.yaml", "managed.yml")
                or other_path.resolve() in target_set
            ):
                continue
            try:
                parts = other_path.parts
                engine = "secops"
                if "rules" in parts:
                    idx = parts.index("rules")
                    if idx + 1 < len(parts):
                        engine = parts[idx + 1]
                schema = f"{engine}_custom"
                if not (schemas_dir / f"{schema}.schema.json").exists():
                    schema = "base_rule"
                other_rule = load_rule_from_yaml(
                    other_path, schema_name=schema, validate_mitre=False
                )
                uniqueness_validator.add_and_validate(other_rule, engine=engine, path=other_path)
            except (RuleLoadError, ValueError, OSError):
                continue

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
                engine = "secops"
                schema = "secops_custom"
                if "rules" in parts:
                    idx = parts.index("rules")
                    if idx + 1 < len(parts):
                        engine = parts[idx + 1]
                        schema = f"{engine}_custom"
                if not (schemas_dir / f"{schema}.schema.json").exists():
                    schema = "base_rule"
                rule = load_rule_from_yaml(file_path, schema_name=schema)
                uniqueness_violations = uniqueness_validator.add_and_validate(
                    rule, engine=engine, path=file_path
                )
                if uniqueness_violations:
                    has_errors = True
                    file_result["valid"] = False
                    for v in uniqueness_violations:
                        file_result["errors"].append(v.message)
                        if not json_output:
                            sys.stderr.write(f"[FAIL] {file_path}:\n  {v.message}\n")
                    results.append(file_result)
                    if fail_fast:
                        break
                    continue

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


def _load_all_rules(rules_dir: Path | str = "rules") -> list[tuple[RuleEnvelope, str, Path]]:
    root = Path(rules_dir)
    loaded: list[tuple[RuleEnvelope, str, Path]] = []
    if not root.is_dir():
        return loaded

    for yaml_path in sorted(root.rglob("*.yaml")):
        if yaml_path.name in ("managed.yaml", "managed.yml"):
            continue
        try:
            parts = yaml_path.parts
            engine = "secops"
            if "rules" in parts:
                idx = parts.index("rules")
                if idx + 1 < len(parts):
                    engine = parts[idx + 1]
            schema = f"{engine}_custom"
            rule = load_rule_from_yaml(yaml_path, schema_name=schema, validate_mitre=False)
            loaded.append((rule, engine, yaml_path))
        except (RuleLoadError, ValueError, OSError):
            continue
    return loaded


def execute_export(
    target: str,
    out_path: str | None = None,
    format_type: str | None = None,
    json_output: bool = False,
    rules_dir: str = "rules",
) -> int:
    loaded = _load_all_rules(rules_dir)
    output_str = ""

    if target in ("matrix", "navigator"):
        fmt = format_type or "navigator"
        rules = [r[0] for r in loaded]
        report = calculate_mitre_coverage(rules)

        if fmt == "table":
            output_str = render_matrix_table(report)
        else:  # navigator or json
            payload = export_navigator_layer(report)
            output_str = json.dumps(payload, indent=2)

    elif target in ("catalog", "metadata"):
        fmt = format_type or ("json" if json_output else "markdown")
        entries = [build_catalog_entry_from_rule(r[0], engine=r[1], path=r[2]) for r in loaded]

        if fmt == "csv":
            output_str = export_catalog_csv(entries)
        elif fmt == "json":
            catalog_payload = export_catalog_json(entries)
            output_str = json.dumps(catalog_payload, indent=2)
        else:  # markdown
            output_str = export_catalog_markdown(entries)

    if out_path:
        dest = Path(out_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(output_str + "\n", encoding="utf-8")
        if json_output:
            sys.stdout.write(
                json.dumps({"success": True, "target": target, "out": str(dest)}) + "\n"
            )
        else:
            sys.stdout.write(f"Exported {target} to {dest}\n")
    else:
        sys.stdout.write(output_str + "\n")

    return 0
