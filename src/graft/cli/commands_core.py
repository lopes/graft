import csv
import io
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
from graft.core.loader import (
    DatasetLoadError,
    RuleLoadError,
    load_dataset_from_yaml,
    load_rule_from_yaml,
)
from graft.core.matrix import (
    calculate_mitre_coverage,
    export_navigator_layer,
    render_matrix_table,
)
from graft.core.mitre_intelligence import (
    build_mitre_coverage_report,
    calculate_mitre_gaps,
    export_gaps_csv,
    export_gaps_json,
    export_gaps_markdown,
    export_mitre_coverage_csv,
    export_mitre_coverage_json,
    export_mitre_coverage_markdown,
    filter_technique_ids,
    inspect_mitre_entities,
    load_mitre_analytics,
    load_mitre_database,
    render_gaps_table,
    render_inspect_text,
    render_mitre_coverage_table,
)
from graft.core.models.managed import ManagedState
from graft.core.models.rule import RuleEnvelope
from graft.core.ports.engine import EngineAdapter
from graft.core.validation import RuleUniquenessValidator
from graft.core.validation.mitre_validator import (
    check_upstream_mitre_version,
    update_mitre_taxonomy,
)
from graft.core.validation.schema_validator import SchemaValidator

_MANIFEST_FILENAMES = ("index.yaml", "index.yml")


def _iter_yaml_files(directory: Path) -> list[Path]:
    files = sorted(
        f
        for f in directory.rglob("*.yaml")
        if not any(part.startswith("_") for part in f.relative_to(directory).parts)
    )
    files.extend(
        sorted(
            f
            for f in directory.rglob("*.yml")
            if not any(part.startswith("_") for part in f.relative_to(directory).parts)
        )
    )
    return files


def _is_dataset_path(file_path: Path, datasets_dir: str) -> bool:
    if "datasets" in file_path.parts:
        return True
    try:
        file_path.resolve().relative_to(Path(datasets_dir).resolve())
        return True
    except ValueError:
        return False


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
    datasets_dir: str | None = None,
    fail_fast: bool = False,
    json_output: bool = False,
) -> int:
    resolved_datasets_dir = (
        datasets_dir
        if datasets_dir is not None
        else (str(Path(rules_dir).parent / "datasets") if rules_dir != "rulesets" else "datasets")
    )
    target_files: list[Path] = []
    if paths:
        for p_str in paths:
            p = Path(p_str)
            if p.is_dir():
                target_files.extend(_iter_yaml_files(p))
            elif p.is_file():
                target_files.append(p)
            else:
                err_msg = f"Path not found: {p}"
                if json_output:
                    sys.stdout.write(json.dumps({"success": False, "error": err_msg}) + "\n")
                else:
                    sys.stderr.write(f"Error: {err_msg}\n")
                return 1
    else:
        root_datasets = Path(resolved_datasets_dir)
        if root_datasets.is_dir():
            target_files.extend(_iter_yaml_files(root_datasets))
        root_rules = Path(rules_dir)
        if root_rules.is_dir():
            target_files.extend(_iter_yaml_files(root_rules))

    results: list[dict[str, Any]] = []
    has_errors = False
    uniqueness_validator = RuleUniquenessValidator()
    schema_validator = SchemaValidator()
    registry = EngineRegistry()
    adapters: dict[str, EngineAdapter | None] = {}
    managed_states: dict[tuple[str, Path], ManagedState | None] = {}
    seen_datasets: dict[str, Path] = {}
    local_dataset_names: set[str] = set()

    for candidate_ds_dir in {Path(resolved_datasets_dir), Path("datasets")}:
        if candidate_ds_dir.is_dir():
            for ds_path in _iter_yaml_files(candidate_ds_dir):
                try:
                    ds = load_dataset_from_yaml(ds_path)
                    local_dataset_names.add(ds.metadata.name)
                except (DatasetLoadError, ValueError, OSError):
                    local_dataset_names.add(ds_path.stem)

    target_set = {f.resolve() for f in target_files if f.exists()}
    root_rules = Path(rules_dir)
    if root_rules.is_dir():
        for other_path in _iter_yaml_files(root_rules):
            if other_path.name in _MANIFEST_FILENAMES or other_path.resolve() in target_set:
                continue
            try:
                engine = _infer_engine_from_path(other_path)
                other_rule = load_rule_from_yaml(other_path, validate_mitre=False)
                uniqueness_validator.add_and_validate(other_rule, engine=engine, path=other_path)
            except (RuleLoadError, ValueError, OSError):
                continue

    for file_path in target_files:
        is_dataset = _is_dataset_path(file_path, resolved_datasets_dir)
        is_manifest = not is_dataset and file_path.name in _MANIFEST_FILENAMES
        is_managed_rule = not is_dataset and not is_manifest and "managed" in file_path.parts
        file_type = (
            "dataset"
            if is_dataset
            else ("managed" if (is_manifest or is_managed_rule) else "custom")
        )
        file_result: dict[str, Any] = {
            "path": str(file_path),
            "type": file_type,
            "valid": False,
            "errors": [],
        }

        try:
            if is_dataset:
                dataset = load_dataset_from_yaml(file_path)
                local_dataset_names.add(dataset.metadata.name)
                prev_ds_path = seen_datasets.get(dataset.metadata.name)
                if prev_ds_path is not None and prev_ds_path.resolve() != file_path.resolve():
                    raise DatasetLoadError(
                        f"Duplicate dataset name '{dataset.metadata.name}' in "
                        f"'{file_path}' (already defined in '{prev_ds_path}')"
                    )
                seen_datasets[dataset.metadata.name] = file_path
            else:
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

                    if engine not in adapters:
                        try:
                            adapters[engine] = registry.load_adapter(engine)
                        except Exception:
                            adapters[engine] = None
                    adapter = adapters[engine]

                    if not rule.is_managed and adapter is not None:
                        adapter.validate_rule_dataset_references(rule, local_dataset_names)

                    if rule.is_managed and rule.managed is not None:
                        index_path = _resolve_index_manifest_path(file_path, engine, rules_dir)
                        if not index_path.is_file():
                            raise ValueError(
                                f"Managed index manifest not found at '{index_path}' "
                                f"to validate managed.id '{rule.managed.id}'"
                            )
                        if adapter is not None:
                            cache_key = (engine, index_path.resolve())
                            if cache_key not in managed_states:
                                managed_states[cache_key] = adapter.load_managed_manifest(
                                    index_path
                                )
                            state = managed_states[cache_key]
                            if state is not None and not adapter.has_managed_rule_id(
                                rule.managed.id, state
                            ):
                                raise ValueError(
                                    f"Managed rule ID '{rule.managed.id}' in "
                                    f"'{rule.metadata.name}' not found in '{index_path}'"
                                )

            file_result["valid"] = True
            if not json_output:
                sys.stdout.write(f"[PASS] {file_path}\n")
        except (DatasetLoadError, RuleLoadError, ValueError, Exception) as exc:
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
    version: str | None = None,
    check_only: bool = False,
) -> int:
    try:
        if check_only:
            status = check_upstream_mitre_version()
            cur = status["current_version"]
            lat = status["latest_version"]
            avail = bool(status["update_available"])
            if json_output:
                sys.stdout.write(json.dumps({"success": True, **status}, indent=2) + "\n")
                return 0
            if status.get("offline"):
                sys.stdout.write(
                    f"MITRE ATT&CK pinned at v{cur} (upstream version check skipped: offline).\n"
                )
            elif avail:
                sys.stderr.write(
                    f"[WARNING] MITRE ATT&CK v{lat} is available upstream "
                    f"(current: v{cur}). Run 'graft mitre update' to upgrade.\n"
                )
            else:
                sys.stdout.write(f"MITRE ATT&CK taxonomy is up to date (v{cur}).\n")
            return 0

        payload = update_mitre_taxonomy(source_url=source_url, version=version)
        load_mitre_database.cache_clear()
        load_mitre_analytics.cache_clear()

        resolved_ver = str(payload.get("version", ""))
        tech_count = len(payload.get("techniques", {}))
        tactic_count = len(payload.get("tactics", {}))
        group_count = len(payload.get("groups", {}))
        mit_count = len(payload.get("mitigations", {}))
        det_count = len(payload.get("detection_strategies", {}))
        dc_count = len(payload.get("data_components", {}))
        an_count = int(payload.get("analytics_count", 0))
        msg = (
            f"Updated MITRE ATT&CK Enterprise taxonomy to v{resolved_ver} "
            f"({tech_count} techniques, {tactic_count} tactics, {det_count} strategies, "
            f"{an_count} analytics, {dc_count} data components, {group_count} groups, "
            f"{mit_count} mitigations)."
        )
        if json_output:
            sys.stdout.write(
                json.dumps(
                    {
                        "success": True,
                        "version": resolved_ver,
                        "techniques": tech_count,
                        "tactics": tactic_count,
                        "detection_strategies": det_count,
                        "analytics": an_count,
                        "data_components": dc_count,
                        "groups": group_count,
                        "mitigations": mit_count,
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

    for yaml_path in _iter_yaml_files(root):
        if yaml_path.name in _MANIFEST_FILENAMES:
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
            ):
                if candidate.is_file():
                    try:
                        state = adapter.load_managed_manifest(candidate)
                    except Exception:
                        state = None
                    break
        managed_states[eng] = state
    return adapters, managed_states


def execute_engines(json_output: bool = False) -> int:
    registry = EngineRegistry()
    manifests = registry.list_engines()
    engines_payload: list[dict[str, Any]] = []
    cwd = Path.cwd().resolve()

    for m in manifests:
        eng_dir = registry.get_engine_dir(m.name)
        schemas_dir = eng_dir / "schemas"
        schema_paths: list[str] = []
        if schemas_dir.is_dir():
            for sf in sorted(schemas_dir.glob("*.schema.json")):
                try:
                    schema_paths.append(str(sf.resolve().relative_to(cwd)))
                except ValueError:
                    schema_paths.append(str(sf))

        engines_payload.append(
            {
                "name": m.name,
                "display_name": m.display_name,
                "description": m.description,
                "adapter_class": m.adapter_class,
                "environments": list(m.environments),
                "capabilities": {
                    "datasets": m.capabilities.datasets,
                    "custom_rules": m.capabilities.custom_rules,
                    "managed_rules": m.capabilities.managed_rules,
                    "syntax_verification": m.capabilities.syntax_verification,
                    "replay_testing": m.capabilities.replay_testing,
                },
                "schemas": schema_paths,
            }
        )

    if json_output:
        sys.stdout.write(
            json.dumps(
                {
                    "success": True,
                    "total": len(engines_payload),
                    "engines": engines_payload,
                },
                indent=2,
            )
            + "\n"
        )
        return 0

    lines = [
        f"{'Engine':<12} | {'Display Name':<18} | {'Environments':<20} | Capabilities",
        "-" * 88,
    ]
    for item in engines_payload:
        caps_obj = item["capabilities"]
        enabled_caps = [k for k, v in caps_obj.items() if v]
        envs_str = ", ".join(item["environments"])
        caps_str = ", ".join(enabled_caps)
        lines.append(
            f"{item['name']:<12} | {item['display_name']:<18} | {envs_str:<20} | {caps_str}"
        )
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


def _export_datasets_payload(datasets_dir: str) -> list[dict[str, Any]]:
    root = Path(datasets_dir)
    if not root.is_dir():
        return []
    payload: list[dict[str, Any]] = []
    for ds_path in _iter_yaml_files(root):
        try:
            ds = load_dataset_from_yaml(ds_path)
            payload.append(
                {
                    "name": ds.metadata.name,
                    "description": ds.metadata.description,
                    "owners": list(ds.metadata.owners),
                    "tags": list(ds.metadata.tags),
                    "references": list(ds.metadata.references),
                    "value_count": len(ds.values),
                    "values": list(ds.values),
                }
            )
        except (DatasetLoadError, ValueError, OSError):
            continue
    return payload


def execute_export(
    target: str,
    out_path: str | None = None,
    format_type: str | None = None,
    json_output: bool = False,
    rules_dir: str = "rulesets",
    datasets_dir: str = "datasets",
    engine: str | None = None,
    color: str = "#008744",
    platform: str | None = None,
    group: str | None = None,
    data_component: str | None = None,
    enrich: bool = False,
    include_gaps: bool = False,
) -> int:
    output_str = ""

    if target == "datasets":
        fmt = format_type or ("json" if json_output else "table")
        ds_items = _export_datasets_payload(datasets_dir)
        if fmt == "json":
            output_str = json.dumps(ds_items, indent=2)
        elif fmt == "csv":
            buf = io.StringIO()
            writer = csv.writer(buf, lineterminator="\n")
            writer.writerow(["name", "description", "owners", "tags", "value_count", "values"])
            for item in ds_items:
                writer.writerow(
                    [
                        item["name"],
                        item["description"],
                        ";".join(item["owners"]),
                        ";".join(item["tags"]),
                        item["value_count"],
                        ";".join(item["values"]),
                    ]
                )
            output_str = buf.getvalue().rstrip("\n")
        else:
            lines = [
                f"{'Dataset Name':<28} | {'Values':<6} | {'Owners':<20} | Description",
                "-" * 92,
            ]
            for item in ds_items:
                owners_str = ", ".join(item["owners"])
                lines.append(
                    f"{item['name']:<28} | {item['value_count']:<6} | "
                    f"{owners_str:<20} | {item['description']}"
                )
            output_str = "\n".join(lines)
    else:
        loaded = _load_all_rules(rules_dir)
        if engine is not None:
            loaded = [r for r in loaded if r[1] == engine]

        engines_set = {r[1] for r in loaded}
        adapters, managed_states = _load_engine_adapters_and_states(engines_set, rules_dir)

        if target in ("navigator", "matrix", "mitre"):
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
            report = calculate_mitre_coverage(
                enriched_loaded,
                platform=platform,
                group=group,
                data_component=data_component,
            )

            if fmt == "table":
                output_str = render_matrix_table(report, enrich=enrich)
            else:  # navigator or json
                layer_title = (
                    f"Graft Detection Coverage ({engine})" if engine else "Graft Detection Coverage"
                )
                payload = export_navigator_layer(
                    report,
                    layer_name=layer_title,
                    color=color,
                    platform=platform,
                    group=group,
                    data_component=data_component,
                    enrich=enrich,
                    include_gaps=include_gaps,
                )
                output_str = json.dumps(payload, indent=2)

        elif target in ("catalog", "metadata"):
            fmt = format_type or ("json" if json_output else "table")
            has_scope_filter = any(x is not None for x in (platform, group, data_component))
            allowed_techs = (
                filter_technique_ids(
                    platform=platform,
                    group=group,
                    data_component=data_component,
                )
                if has_scope_filter
                else None
            )
            entries: list[CatalogEntry] = []
            for rule, r_engine, rule_path in loaded:
                if allowed_techs is not None:
                    rule_techs = {t for ts in rule.metadata.mitre.values() for t in ts}
                    if not (rule_techs & allowed_techs):
                        continue
                entry = build_catalog_entry_from_rule(
                    rule,
                    engine=r_engine,
                    path=rule_path,
                    adapter=adapters.get(r_engine),
                    managed_state=managed_states.get(r_engine),
                )
                entries.append(entry)

            if fmt == "csv":
                output_str = export_catalog_csv(entries, enrich=enrich)
            elif fmt == "json":
                catalog_payload = export_catalog_json(entries, enrich=enrich)
                output_str = json.dumps(catalog_payload, indent=2)
            elif fmt == "markdown":
                output_str = export_catalog_markdown(entries, enrich=enrich)
            else:  # table
                output_str = render_catalog_table(entries, enrich=enrich)

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


def _load_enriched_rules_for_mitre(
    rules_dir: str = "rulesets",
    engine: str | None = None,
) -> list[tuple[RuleEnvelope, str, Path, str]]:
    loaded = _load_all_rules(rules_dir)
    if engine is not None:
        loaded = [r for r in loaded if r[1] == engine]
    engines_set = {r[1] for r in loaded}
    adapters, managed_states = _load_engine_adapters_and_states(engines_set, rules_dir)
    return [
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


def execute_mitre_coverage(
    rules_dir: str = "rulesets",
    engine: str | None = None,
    platform: str | None = None,
    group: str | None = None,
    tactic: str | None = None,
    technique: str | None = None,
    det: str | None = None,
    data_component: str | None = None,
    tag: str | None = None,
    enrich: bool = False,
    format_type: str | None = None,
    out_path: str | None = None,
    json_output: bool = False,
) -> int:
    enriched_loaded = _load_enriched_rules_for_mitre(rules_dir, engine=engine)
    report = build_mitre_coverage_report(
        enriched_loaded,
        platform=platform,
        group=group,
        tactic=tactic,
        technique=technique,
        det=det,
        data_component=data_component,
        tag=tag,
        enrich=enrich,
    )
    fmt = format_type or ("json" if json_output else "table")
    if fmt == "json":
        output_str = json.dumps(export_mitre_coverage_json(report, enrich=enrich), indent=2)
    elif fmt == "csv":
        output_str = export_mitre_coverage_csv(report, enrich=enrich)
    elif fmt == "markdown":
        output_str = export_mitre_coverage_markdown(report, enrich=enrich)
    else:
        output_str = render_mitre_coverage_table(report, enrich=enrich)

    if out_path:
        dest = Path(out_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(output_str + "\n", encoding="utf-8")
        if json_output:
            sys.stdout.write(
                json.dumps({"success": True, "target": "coverage", "out": str(dest)}) + "\n"
            )
        else:
            sys.stdout.write(f"Exported MITRE coverage to {dest}\n")
    else:
        sys.stdout.write(output_str + "\n")
    return 0


def execute_mitre_gaps(
    rules_dir: str = "rulesets",
    engine: str | None = None,
    platform: str | None = None,
    group: str | None = None,
    tactic: str | None = None,
    data_component: str | None = None,
    infer_scope: bool = False,
    top: int | None = None,
    format_type: str | None = None,
    out_path: str | None = None,
    json_output: bool = False,
) -> int:
    enriched_loaded = _load_enriched_rules_for_mitre(rules_dir, engine=engine)
    fmt = format_type or ("json" if json_output else "table")
    effective_top = top if top is not None else (25 if fmt == "table" else None)
    report = calculate_mitre_gaps(
        enriched_loaded,
        platform=platform,
        group=group,
        tactic=tactic,
        data_component=data_component,
        infer_scope=infer_scope,
        top=effective_top,
    )
    if fmt == "json":
        output_str = json.dumps(export_gaps_json(report), indent=2)
    elif fmt == "csv":
        output_str = export_gaps_csv(report)
    elif fmt == "markdown":
        output_str = export_gaps_markdown(report)
    else:
        output_str = render_gaps_table(report)

    if out_path:
        dest = Path(out_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(output_str + "\n", encoding="utf-8")
        if json_output:
            sys.stdout.write(
                json.dumps({"success": True, "target": "gaps", "out": str(dest)}) + "\n"
            )
        else:
            sys.stdout.write(f"Exported MITRE gaps to {dest}\n")
    else:
        sys.stdout.write(output_str + "\n")
    return 0


def execute_mitre_inspect(
    targets: list[str],
    rules_dir: str = "rulesets",
    platform: str | None = None,
    include_analytics: bool = False,
    include_groups: bool = False,
    full: bool = False,
    json_output: bool = False,
) -> int:
    enriched_loaded = _load_enriched_rules_for_mitre(rules_dir)
    items = inspect_mitre_entities(
        targets,
        rules=enriched_loaded,
        platform=platform,
        include_analytics=include_analytics,
        include_groups=include_groups,
        full=full,
    )
    if json_output:
        version = str(load_mitre_database().get("version", ""))
        sys.stdout.write(
            json.dumps(
                {
                    "success": True,
                    "version": version,
                    "total": len(items),
                    "items": items,
                },
                indent=2,
            )
            + "\n"
        )
    else:
        sys.stdout.write(render_inspect_text(items) + "\n")
    return 0
