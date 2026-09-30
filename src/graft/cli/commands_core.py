import json
import sys
from pathlib import Path
from typing import Any

import yaml

from graft.core.catalog import (
    CatalogEntry,
    build_catalog_entry_from_rule,
    export_catalog_csv,
    export_catalog_json,
    export_catalog_markdown,
    render_catalog_table,
    resolve_rule_deployment_status,
)
from graft.core.engine_registry import EngineRegistry
from graft.core.loader import RuleLoadError, load_rule_from_yaml
from graft.core.matrix import (
    calculate_mitre_coverage,
    export_navigator_layer,
    render_matrix_table,
)
from graft.core.models.managed import ManagedState
from graft.core.models.rule import RuleEnvelope
from graft.core.ports.engine import EngineAdapter
from graft.core.validation import RuleUniquenessValidator
from graft.core.validation.mitre_validator import update_mitre_taxonomy
from graft.core.validation.schema_validator import SchemaValidator

_MANIFEST_FILENAMES = ("index.yaml", "index.yml", "managed.yaml", "managed.yml")


def _infer_engine_from_path(file_path: Path) -> str:
    parts = file_path.parts
    if "rulesets" in parts:
        idx = parts.index("rulesets")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    elif "rules" in parts:
        idx = parts.index("rules")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    engines = EngineRegistry().list_engines()
    if engines:
        return engines[0].name
    return "custom"


def _resolve_index_manifest_path(rule_path: Path, engine: str, rules_dir: str) -> Path:
    for candidate_name in ("index.yaml", "index.yml"):
        sibling = rule_path.parent / candidate_name
        if sibling.is_file():
            return sibling
    for candidate_name in ("index.yaml", "index.yml"):
        candidate = Path(rules_dir) / engine / "managed" / candidate_name
        if candidate.is_file():
            return candidate
    return rule_path.parent / "index.yaml"


def execute_lint(
    paths: list[str] | None = None,
    rules_dir: str = "rulesets",
    fail_fast: bool = False,
    json_output: bool = False,
) -> int:
    target_files: list[Path] = []
    if paths:
        for p_str in paths:
            p = Path(p_str)
            if p.is_dir():
                target_files.extend(
                    sorted(
                        f
                        for f in p.rglob("*.yaml")
                        if not any(part.startswith("_") for part in f.parts)
                    )
                )
                target_files.extend(
                    sorted(
                        f
                        for f in p.rglob("*.yml")
                        if not any(part.startswith("_") for part in f.parts)
                    )
                )
            elif p.is_file():
                target_files.append(p)
            else:
                if not json_output:
                    sys.stderr.write(f"Error: Path not found: {p}\n")
                return 1
    else:
        root_rules = Path(rules_dir)
        if root_rules.is_dir():
            target_files.extend(
                sorted(
                    f
                    for f in root_rules.rglob("*.yaml")
                    if not any(part.startswith("_") for part in f.parts)
                )
            )
            target_files.extend(
                sorted(
                    f
                    for f in root_rules.rglob("*.yml")
                    if not any(part.startswith("_") for part in f.parts)
                )
            )

    results: list[dict[str, Any]] = []
    has_errors = False
    uniqueness_validator = RuleUniquenessValidator()
    schema_validator = SchemaValidator()
    registry = EngineRegistry()
    adapters: dict[str, EngineAdapter | None] = {}
    managed_states: dict[tuple[str, Path], ManagedState | None] = {}

    target_set = {f.resolve() for f in target_files if f.exists()}
    root_rules = Path(rules_dir)
    if root_rules.is_dir():
        for other_path in sorted(root_rules.rglob("*.yaml")):
            if (
                other_path.name in _MANIFEST_FILENAMES
                or any(part.startswith("_") for part in other_path.parts)
                or other_path.resolve() in target_set
            ):
                continue
            try:
                engine = _infer_engine_from_path(other_path)
                other_rule = load_rule_from_yaml(other_path, validate_mitre=False)
                uniqueness_validator.add_and_validate(other_rule, engine=engine, path=other_path)
            except (RuleLoadError, ValueError, OSError):
                continue

    for file_path in target_files:
        is_manifest = file_path.name in _MANIFEST_FILENAMES
        is_managed_rule = not is_manifest and "managed" in file_path.parts
        file_result: dict[str, Any] = {
            "path": str(file_path),
            "type": "managed" if (is_manifest or is_managed_rule) else "custom",
            "valid": False,
            "errors": [],
        }

        try:
            engine = _infer_engine_from_path(file_path)

            if is_manifest:
                raw_text = file_path.read_text(encoding="utf-8")
                manifest_data: Any = yaml.safe_load(raw_text)
                if not isinstance(manifest_data, dict):
                    raise ValueError("Managed manifest content must be a YAML mapping")

                avail = schema_validator.available_schemas()
                schema_to_use = None
                for candidate in (f"{engine}:managed", f"{engine}_managed", "managed"):
                    if candidate in avail:
                        schema_to_use = candidate
                        break

                if schema_to_use is None:
                    raise ValueError(
                        f"Engine '{engine}' does not provide a managed manifest schema"
                    )

                errs = schema_validator.validate(manifest_data, schema_name=schema_to_use)
                if errs:
                    err_details = "; ".join(f"{e.path}: {e.message}" for e in errs)
                    raise ValueError(f"Managed manifest validation failed: {err_details}")
            else:
                rule = load_rule_from_yaml(file_path)
                file_result["type"] = rule.rule_type
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

                if rule.is_managed and rule.managed is not None:
                    index_path = _resolve_index_manifest_path(file_path, engine, rules_dir)
                    if not index_path.is_file():
                        raise ValueError(
                            f"Managed index manifest not found at '{index_path}' "
                            f"to validate managed.id '{rule.managed.id}'"
                        )
                    if engine not in adapters:
                        try:
                            adapters[engine] = registry.load_adapter(engine)
                        except Exception:
                            adapters[engine] = None
                    adapter = adapters[engine]
                    if adapter is not None:
                        cache_key = (engine, index_path.resolve())
                        if cache_key not in managed_states:
                            managed_states[cache_key] = adapter.load_managed_manifest(index_path)
                        state = managed_states[cache_key]
                        if state is not None and not adapter.has_managed_rule_id(
                            rule.managed.id, state
                        ):
                            raise ValueError(
                                f"Managed rule ID '{rule.managed.id}' in '{rule.metadata.name}' "
                                f"not found in '{index_path}'"
                            )

            file_result["valid"] = True
            if not json_output:
                sys.stdout.write(f"[PASS] {file_path}\n")
        except (RuleLoadError, ValueError, Exception) as exc:
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
    try:
        payload = update_mitre_taxonomy(source_url=source_url)
        version = payload.get("version", "19.2")
        tech_count = len(payload.get("techniques", {}))
        tactic_count = len(payload.get("tactics", {}))
        msg = (
            f"Updated MITRE ATT&CK Enterprise taxonomy to v{version} "
            f"({tech_count} techniques, {tactic_count} tactics)."
        )
        if json_output:
            sys.stdout.write(
                json.dumps(
                    {
                        "success": True,
                        "version": version,
                        "techniques": tech_count,
                        "tactics": tactic_count,
                        "message": msg,
                    }
                )
                + "\n"
            )
        else:
            sys.stdout.write(f"{msg}\n")
        return 0
    except Exception as exc:
        err_msg = f"Failed updating MITRE ATT&CK taxonomy: {exc}"
        if json_output:
            sys.stdout.write(json.dumps({"success": False, "error": err_msg}) + "\n")
        else:
            sys.stderr.write(f"[ERROR] {err_msg}\n")
        return 1


def _load_all_rules(rules_dir: Path | str = "rulesets") -> list[tuple[RuleEnvelope, str, Path]]:
    root = Path(rules_dir)
    loaded: list[tuple[RuleEnvelope, str, Path]] = []
    if not root.is_dir():
        return loaded

    for yaml_path in sorted(root.rglob("*.yaml")):
        if yaml_path.name in _MANIFEST_FILENAMES or any(
            part.startswith("_") for part in yaml_path.parts
        ):
            continue
        try:
            engine = _infer_engine_from_path(yaml_path)
            rule = load_rule_from_yaml(yaml_path, validate_mitre=False)
            loaded.append((rule, engine, yaml_path))
        except (RuleLoadError, ValueError, OSError):
            continue
    return loaded


def _load_engine_adapters_and_states(
    engines: set[str],
    rules_dir: str,
) -> tuple[dict[str, EngineAdapter | None], dict[str, ManagedState | None]]:
    registry = EngineRegistry()
    adapters: dict[str, EngineAdapter | None] = {}
    managed_states: dict[str, ManagedState | None] = {}
    for eng in engines:
        try:
            adapter = registry.load_adapter(eng)
        except Exception:
            adapter = None
        adapters[eng] = adapter
        state: ManagedState | None = None
        if adapter is not None:
            for candidate in (
                Path(rules_dir) / eng / "managed" / "index.yaml",
                Path(rules_dir) / eng / "managed" / "index.yml",
                Path(rules_dir) / eng / "managed.yaml",
            ):
                if candidate.is_file():
                    try:
                        state = adapter.load_managed_manifest(candidate)
                    except Exception:
                        state = None
                    break
        managed_states[eng] = state
    return adapters, managed_states


def execute_export(
    target: str,
    out_path: str | None = None,
    format_type: str | None = None,
    json_output: bool = False,
    rules_dir: str = "rulesets",
    engine: str | None = None,
    color: str = "#008744",
) -> int:
    loaded = _load_all_rules(rules_dir)
    if engine is not None:
        loaded = [r for r in loaded if r[1] == engine]

    engines_set = {r[1] for r in loaded}
    adapters, managed_states = _load_engine_adapters_and_states(engines_set, rules_dir)

    output_str = ""

    if target in ("matrix", "navigator"):
        fmt = format_type or ("json" if json_output else "navigator")
        enriched_loaded = [
            (
                rule,
                r_engine,
                rule_path,
                resolve_rule_deployment_status(
                    rule,
                    engine=r_engine,
                    adapter=adapters.get(r_engine),
                    managed_state=managed_states.get(r_engine),
                ),
            )
            for rule, r_engine, rule_path in loaded
        ]
        report = calculate_mitre_coverage(enriched_loaded)

        if fmt == "table":
            output_str = render_matrix_table(report)
        else:  # navigator or json
            layer_title = (
                f"Graft Detection Coverage ({engine})" if engine else "Graft Detection Coverage"
            )
            payload = export_navigator_layer(report, layer_name=layer_title, color=color)
            output_str = json.dumps(payload, indent=2)

    elif target in ("catalog", "metadata"):
        fmt = format_type or ("json" if json_output else "table")
        entries: list[CatalogEntry] = []
        for rule, r_engine, rule_path in loaded:
            entry = build_catalog_entry_from_rule(
                rule,
                engine=r_engine,
                path=rule_path,
                adapter=adapters.get(r_engine),
                managed_state=managed_states.get(r_engine),
            )
            entries.append(entry)

        if fmt == "csv":
            output_str = export_catalog_csv(entries)
        elif fmt == "json":
            catalog_payload = export_catalog_json(entries)
            output_str = json.dumps(catalog_payload, indent=2)
        elif fmt == "markdown":
            output_str = export_catalog_markdown(entries)
        else:  # table
            output_str = render_catalog_table(entries)

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
