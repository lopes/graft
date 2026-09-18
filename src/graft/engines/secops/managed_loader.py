from pathlib import Path
from typing import Any, cast

import yaml

from graft.core.models.managed import (
    ManagedDeployment,
    ManagedExclusion,
    ManagedRuleSet,
    ManagedState,
)
from graft.core.validation.schema_validator import SchemaValidator


class ManagedManifestLoadError(Exception):
    pass


def _parse_deployments(rs: dict[str, Any]) -> list[ManagedDeployment]:
    deployments_raw = rs.get("deployments", [])
    deployments: list[ManagedDeployment] = []
    if isinstance(deployments_raw, list):
        for dep in deployments_raw:
            if not isinstance(dep, dict):
                continue
            deployments.append(
                ManagedDeployment(
                    type=str(dep.get("type", "")),
                    enabled=bool(dep.get("enabled", False)),
                    alerting=bool(dep.get("alerting", False)),
                )
            )
    return deployments


def load_managed_manifest_from_str(content: str) -> ManagedState:
    try:
        data: Any = yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise ManagedManifestLoadError(f"YAML parsing error: {e}") from e

    if not isinstance(data, dict):
        raise ManagedManifestLoadError("Manifest content must be a YAML mapping")

    validator = SchemaValidator()
    errors = validator.validate(data, schema_name="secops_managed")
    if errors:
        error_lines = "\n".join(f"- {err.path}: {err.message}" for err in errors)
        raise ManagedManifestLoadError(f"Schema validation failed:\n{error_lines}")

    rulesets: list[ManagedRuleSet] = []
    if "categories" in data and isinstance(data["categories"], list):
        for cat in data["categories"]:
            if not isinstance(cat, dict):
                continue
            cat_name = str(cat.get("name", ""))
            cat_id = str(cat.get("id", ""))
            raw_rulesets = cat.get("rulesets", [])
            if isinstance(raw_rulesets, list):
                for raw_rs in raw_rulesets:
                    if not isinstance(raw_rs, dict):
                        continue
                    deployments = _parse_deployments(raw_rs)
                    rulesets.append(
                        ManagedRuleSet(
                            id=str(raw_rs.get("id", "")),
                            name=str(raw_rs.get("name", "")),
                            category=cat_name,
                            deployments=tuple(deployments),
                            category_id=cat_id,
                        )
                    )
    elif "rulesets" in data and isinstance(data["rulesets"], list):
        for rs in data["rulesets"]:
            if not isinstance(rs, dict):
                continue
            deployments = _parse_deployments(rs)
            cat_val = str(rs.get("category", ""))
            cat_id = str(rs.get("category_id", cat_val))
            rulesets.append(
                ManagedRuleSet(
                    id=str(rs.get("id", "")),
                    name=str(rs.get("name", "")),
                    category=cat_val,
                    deployments=tuple(deployments),
                    category_id=cat_id,
                )
            )

    exclusions_raw = data.get("exclusions", [])
    exclusions: list[ManagedExclusion] = []
    if isinstance(exclusions_raw, list):
        for ex in exclusions_raw:
            if not isinstance(ex, dict):
                continue
            rule_id = str(ex["rule_id"]) if ex.get("rule_id") is not None else None
            ruleset_id = str(ex["ruleset_id"]) if ex.get("ruleset_id") is not None else None
            exclusions.append(
                ManagedExclusion(
                    id=str(ex.get("id", "")),
                    rule_id=rule_id,
                    ruleset_id=ruleset_id,
                    expression=str(ex.get("expression", "")),
                    description=str(ex.get("description", "")),
                )
            )

    return ManagedState(
        rulesets=tuple(rulesets),
        exclusions=tuple(exclusions),
    )


def load_managed_manifest_from_yaml(path: Path | str) -> ManagedState:
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"Manifest file not found: {file_path}")
    content = file_path.read_text(encoding="utf-8")
    return load_managed_manifest_from_str(content)


def dump_managed_manifest_to_yaml(state: ManagedState, path: Path | str | None = None) -> str:
    categories_map: dict[str, dict[str, object]] = {}

    for rs in state.rulesets:
        cat_key = rs.category or "default"
        if cat_key not in categories_map:
            cat_id = getattr(rs, "category_id", "")
            if not cat_id:
                cat_id = "".join(
                    c if c.isalnum() or c in ("-", "_") else "_" for c in cat_key.lower()
                )
                if not cat_id:
                    cat_id = "default"
            categories_map[cat_key] = {
                "name": cat_key,
                "id": cat_id,
                "rulesets": [],
            }

        deployments_dict: list[dict[str, object]] = []
        for dep in rs.deployments:
            deployments_dict.append(
                {
                    "type": dep.type,
                    "enabled": dep.enabled,
                    "alerting": dep.alerting,
                }
            )

        cast(list[dict[str, object]], categories_map[cat_key]["rulesets"]).append(
            {
                "id": rs.id,
                "name": rs.name,
                "deployments": deployments_dict,
            }
        )

    sorted_categories: list[dict[str, object]] = []
    for cat_name in sorted(categories_map.keys()):
        cat_data = categories_map[cat_name]
        rs_list = cast(list[dict[str, object]], cat_data["rulesets"])
        rs_list.sort(key=lambda r: str(r.get("name", "")))
        sorted_categories.append(cat_data)

    doc: dict[str, object] = {"categories": sorted_categories}

    if state.exclusions:
        exclusions_dict: list[dict[str, object]] = []
        for ex in state.exclusions:
            item: dict[str, object] = {
                "id": ex.id,
                "rule_id": ex.rule_id,
                "ruleset_id": ex.ruleset_id,
                "expression": ex.expression,
            }
            if ex.description:
                item["description"] = ex.description
            exclusions_dict.append(item)
        doc["exclusions"] = exclusions_dict
    else:
        doc["exclusions"] = []

    dumped = str(yaml.safe_dump(doc, sort_keys=False, indent=2))

    if path is not None:
        target_path = Path(path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(dumped, encoding="utf-8")

    return dumped
