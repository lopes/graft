import importlib.resources
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from graft.core.mitre_intelligence import (
    evaluate_technique_coverage_state,
    filter_technique_ids,
    resolve_platform_name,
)
from graft.core.models.rule import RuleEnvelope


@dataclass(frozen=True)
class TechniqueCoverage:
    technique_id: str
    technique_name: str
    tactics: list[str]
    rule_count: int
    rule_names: list[str]
    platforms: list[str] = field(default_factory=list)
    data_components: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    group_count: int = 0


@dataclass(frozen=True)
class TechniqueTacticCoverage:
    technique_id: str
    technique_name: str
    tactic_shortname: str
    rule_count: int
    rule_names: list[str]
    engines: list[str]
    statuses: list[str]
    links: list[dict[str, str]]
    rule_types: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    data_components: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    group_count: int = 0


@dataclass(frozen=True)
class MatrixCoverageReport:
    total_rules: int
    covered_techniques: int
    techniques: list[TechniqueCoverage]
    tactic_coverages: list[TechniqueTacticCoverage]
    version: str = ""


def _load_mitre_full_db() -> dict[str, Any]:
    try:
        resource = importlib.resources.files("graft.data").joinpath("mitre_attack.json")
        content = resource.read_text(encoding="utf-8")
        data: dict[str, Any] = json.loads(content)
        return data
    except (OSError, ValueError, TypeError):
        return {"version": "", "techniques": {}}


def _load_mitre_taxonomy() -> dict[str, dict[str, Any]]:
    data = _load_mitre_full_db()
    techniques: dict[str, dict[str, Any]] = data.get("techniques", {})
    return techniques


def calculate_mitre_coverage(
    rules: Sequence[
        RuleEnvelope
        | tuple[RuleEnvelope, str, Path | str | None]
        | tuple[RuleEnvelope, str, Path | str | None, str]
    ],
    matrix_data: dict[str, dict[str, Any]] | None = None,
    *,
    platform: str | None = None,
    group: str | None = None,
    data_component: str | None = None,
) -> MatrixCoverageReport:
    full_db = _load_mitre_full_db()
    techniques_db = matrix_data if matrix_data is not None else full_db.get("techniques", {})
    version = str(full_db.get("version", ""))

    has_scope_filter = any(x is not None for x in (platform, group, data_component))
    allowed_techs = (
        filter_technique_ids(
            full_db,
            platform=platform,
            group=group,
            data_component=data_component,
        )
        if has_scope_filter
        else None
    )

    normalized: list[tuple[RuleEnvelope, str, str | None, str | None]] = []
    for item in rules:
        if isinstance(item, tuple):
            rule_obj = item[0]
            engine_name = str(item[1]) if len(item) > 1 else "custom"
            path_val = str(item[2]) if len(item) > 2 and item[2] is not None else None
            status_val = str(item[3]) if len(item) > 3 and item[3] is not None else None
            normalized.append((rule_obj, engine_name, path_val, status_val))
        else:
            normalized.append((item, "custom", None, None))

    tech_rules_map: dict[str, set[str]] = {}
    tech_tactics_map: dict[str, set[str]] = {}
    pair_map: dict[tuple[str, str], dict[str, Any]] = {}
    matched_rule_names: set[str] = set()

    for rule, engine, path, explicit_status in normalized:
        rule_name = rule.metadata.name
        if explicit_status is not None:
            status = explicit_status
        elif rule.is_managed or not rule.deployment.enabled:
            status = "disabled"
        elif not rule.deployment.alerting:
            status = "silent"
        else:
            status = "enabled"

        for tactic, tech_list in rule.metadata.mitre.items():
            for tech_id in tech_list:
                if allowed_techs is not None and tech_id not in allowed_techs:
                    continue
                matched_rule_names.add(rule_name)
                tech_rules_map.setdefault(tech_id, set()).add(rule_name)
                tech_tactics_map.setdefault(tech_id, set()).add(tactic)

                pair_key = (tech_id, tactic)
                if pair_key not in pair_map:
                    pair_map[pair_key] = {
                        "rules": [],
                        "engines": set(),
                        "rule_types": set(),
                        "statuses": set(),
                        "links": [],
                    }
                if rule_name not in pair_map[pair_key]["rules"]:
                    pair_map[pair_key]["rules"].append(rule_name)
                pair_map[pair_key]["engines"].add(engine)
                pair_map[pair_key]["rule_types"].add(rule.rule_type)
                pair_map[pair_key]["statuses"].add(status)
                if path:
                    link_obj = {"label": f"Source: {rule_name}", "url": path}
                    if link_obj not in pair_map[pair_key]["links"]:
                        pair_map[pair_key]["links"].append(link_obj)

    coverage_list: list[TechniqueCoverage] = []
    for tech_id in sorted(tech_rules_map.keys()):
        rule_names = sorted(tech_rules_map[tech_id])
        tech_meta = techniques_db.get(tech_id, {})
        tech_name = str(tech_meta.get("name", "Unknown Technique"))
        reported_tactics = tech_meta.get("tactics", [])
        if isinstance(reported_tactics, list) and reported_tactics:
            tactics = [str(t) for t in reported_tactics]
        else:
            tactics = sorted(tech_tactics_map.get(tech_id, set()))

        platforms = [str(p) for p in tech_meta.get("platforms", [])]
        dcs = [str(dc) for dc in tech_meta.get("data_components", [])]
        mits = [str(m) for m in tech_meta.get("mitigations", [])]
        groups_raw = tech_meta.get("groups", [])
        group_count = len(groups_raw) if isinstance(groups_raw, list) else 0

        coverage_list.append(
            TechniqueCoverage(
                technique_id=tech_id,
                technique_name=tech_name,
                tactics=tactics,
                rule_count=len(rule_names),
                rule_names=rule_names,
                platforms=platforms,
                data_components=dcs,
                mitigations=mits,
                group_count=group_count,
            )
        )

    tactic_coverage_list: list[TechniqueTacticCoverage] = []
    for (tech_id, shortname), details in sorted(pair_map.items()):
        tech_meta = techniques_db.get(tech_id, {})
        tech_name = str(tech_meta.get("name", "Unknown Technique"))
        platforms = [str(p) for p in tech_meta.get("platforms", [])]
        dcs = [str(dc) for dc in tech_meta.get("data_components", [])]
        mits = [str(m) for m in tech_meta.get("mitigations", [])]
        groups_raw = tech_meta.get("groups", [])
        group_count = len(groups_raw) if isinstance(groups_raw, list) else 0

        tactic_coverage_list.append(
            TechniqueTacticCoverage(
                technique_id=tech_id,
                technique_name=tech_name,
                tactic_shortname=shortname,
                rule_count=len(details["rules"]),
                rule_names=details["rules"],
                engines=sorted(details["engines"]),
                statuses=sorted(details["statuses"]),
                links=details["links"],
                rule_types=sorted(details["rule_types"]),
                platforms=platforms,
                data_components=dcs,
                mitigations=mits,
                group_count=group_count,
            )
        )

    total_rules_count = len(matched_rule_names) if has_scope_filter else len(normalized)
    return MatrixCoverageReport(
        total_rules=total_rules_count,
        covered_techniques=len(coverage_list),
        techniques=coverage_list,
        tactic_coverages=tactic_coverage_list,
        version=version,
    )


def export_navigator_layer(
    report: MatrixCoverageReport,
    layer_name: str = "Graft Detection Coverage",
    color: str = "#008744",
    attack_version: str | None = None,
    *,
    platform: str | None = None,
    group: str | None = None,
    data_component: str | None = None,
    enrich: bool = False,
    include_gaps: bool = False,
) -> dict[str, Any]:
    full_db = _load_mitre_full_db()
    resolved_version = attack_version or report.version or str(full_db.get("version", ""))
    max_score = max((t.rule_count for t in report.techniques), default=1)

    techniques_payload: list[dict[str, Any]] = []
    sources = report.tactic_coverages if report.tactic_coverages else []
    seen_pairs: set[tuple[str, str]] = set()

    if sources:
        for t in sources:
            if t.tactic_shortname == "none":
                continue
            seen_pairs.add((t.technique_id, t.tactic_shortname))
            comment = (
                f"Covered by {t.rule_count} rule(s): {', '.join(t.rule_names)}"
                if t.rule_count > 1
                else f"Rule: {t.rule_names[0]}"
            )
            types_val = ", ".join(t.rule_types) if t.rule_types else "custom"
            metadata = [
                {"name": "engine", "value": ", ".join(t.engines)},
                {"name": "type", "value": types_val},
                {"name": "rules", "value": ", ".join(t.rule_names)},
                {"name": "status", "value": ", ".join(t.statuses)},
            ]
            if enrich:
                metadata.extend(
                    [
                        {"name": "platforms", "value": ", ".join(t.platforms)},
                        {"name": "data_components", "value": ", ".join(t.data_components)},
                        {"name": "mitigations", "value": ", ".join(t.mitigations)},
                        {"name": "group_count", "value": str(t.group_count)},
                    ]
                )

            techniques_payload.append(
                {
                    "techniqueID": t.technique_id,
                    "tactic": t.tactic_shortname,
                    "score": t.rule_count,
                    "color": "",
                    "comment": comment,
                    "enabled": True,
                    "metadata": metadata,
                    "links": t.links,
                    "showSubtechniques": True,
                }
            )
    else:
        for tc in report.techniques:
            comment = f"Covered by {tc.rule_count} rule(s): {', '.join(tc.rule_names)}"
            meta_list: list[dict[str, str]] = []
            if enrich:
                meta_list = [
                    {"name": "platforms", "value": ", ".join(tc.platforms)},
                    {"name": "data_components", "value": ", ".join(tc.data_components)},
                    {"name": "mitigations", "value": ", ".join(tc.mitigations)},
                    {"name": "group_count", "value": str(tc.group_count)},
                ]
            techniques_payload.append(
                {
                    "techniqueID": tc.technique_id,
                    "score": tc.rule_count,
                    "color": "",
                    "comment": comment,
                    "enabled": True,
                    "metadata": meta_list,
                    "links": [],
                    "showSubtechniques": True,
                }
            )

    if include_gaps:
        in_scope_ids = filter_technique_ids(
            full_db,
            platform=platform,
            group=group,
            data_component=data_component,
        )
        if report.tactic_coverages:
            covered_ids = {
                tc.technique_id
                for tc in report.tactic_coverages
                if any(s != "disabled" for s in tc.statuses)
            }
        else:
            covered_ids = {t.technique_id for t in report.techniques}
        techniques_db = full_db.get("techniques", {})

        for tid in sorted(in_scope_ids):
            state = evaluate_technique_coverage_state(tid, covered_ids, in_scope_ids)
            if state == "covered":
                continue
            tinfo = techniques_db.get(tid, {})
            t_tactics = [str(tac) for tac in tinfo.get("tactics", []) if str(tac) != "none"]
            gap_color = "#fff8e1" if state == "partial" else "#ffebee"
            gap_comment = (
                "Partial coverage (parent or sub-technique covered)"
                if state == "partial"
                else "Uncovered gap"
            )
            for tac_slug in t_tactics:
                if (tid, tac_slug) in seen_pairs:
                    continue
                seen_pairs.add((tid, tac_slug))
                gap_meta = [{"name": "coverage_state", "value": state}]
                if enrich:
                    gap_meta.extend(
                        [
                            {
                                "name": "platforms",
                                "value": ", ".join(str(p) for p in tinfo.get("platforms", [])),
                            },
                            {
                                "name": "data_components",
                                "value": ", ".join(
                                    str(dc) for dc in tinfo.get("data_components", [])
                                ),
                            },
                            {
                                "name": "mitigations",
                                "value": ", ".join(str(m) for m in tinfo.get("mitigations", [])),
                            },
                            {
                                "name": "group_count",
                                "value": str(len(tinfo.get("groups", []))),
                            },
                        ]
                    )
                techniques_payload.append(
                    {
                        "techniqueID": tid,
                        "tactic": tac_slug,
                        "score": 0,
                        "color": gap_color,
                        "comment": gap_comment,
                        "enabled": True,
                        "metadata": gap_meta,
                        "links": [],
                        "showSubtechniques": True,
                    }
                )

    default_platforms = [
        "Linux",
        "macOS",
        "Windows",
        "Network Devices",
        "ESXi",
        "Containers",
        "IaaS",
        "SaaS",
        "Google Workspace",
        "Office Suite",
        "Identity Provider",
    ]
    resolved_platforms = (
        [resolve_platform_name(platform, full_db)] if platform else default_platforms
    )

    return {
        "name": layer_name,
        "versions": {
            "attack": resolved_version,
            "navigator": "5.2.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            f"Graft Detection Coverage Matrix Layer "
            f"({report.total_rules} rules, {report.covered_techniques} techniques)."
        ),
        "filters": {"platforms": resolved_platforms},
        "sorting": 3,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
            "expandedSubtechniques": "annotated",
        },
        "selectTechniquesAcrossTactics": False,
        "gradient": {
            "colors": ["#ffffff", color],
            "minValue": 0,
            "maxValue": max_score,
        },
        "techniques": techniques_payload,
    }


def render_matrix_table(report: MatrixCoverageReport, enrich: bool = False) -> str:
    summary_header = (
        f"MITRE ATT&CK Detection Matrix "
        f"(Total Rules: {report.total_rules} | Covered Techniques: {report.covered_techniques})"
    )
    if not enrich:
        lines: list[str] = [
            summary_header,
            "=" * 90,
            f"{'Technique ID':<15} {'Technique Name':<32} {'Rules':<7} {'Rules / Detections'}",
            "-" * 90,
        ]

        for t in report.techniques:
            rule_summary = ", ".join(t.rule_names)
            if len(rule_summary) > 32:
                rule_summary = rule_summary[:29] + "..."
            tech_name = t.technique_name
            if len(tech_name) > 30:
                tech_name = tech_name[:27] + "..."
            lines.append(f"{t.technique_id:<15} {tech_name:<32} {t.rule_count:<7} {rule_summary}")

        return "\n".join(lines)

    lines = [
        summary_header,
        "=" * 116,
        (
            f"{'Technique ID':<14} {'Technique Name':<28} {'Rules':<6} {'Groups':<7} "
            f"{'Platforms':<20} {'Data Components':<16} {'Rules / Detections'}"
        ),
        "-" * 116,
    ]
    for t in report.techniques:
        tech_name = (
            t.technique_name[:25] + "..." if len(t.technique_name) > 28 else t.technique_name
        )
        plats = ", ".join(t.platforms)
        if len(plats) > 18:
            plats = plats[:15] + "..."
        dcs = ", ".join(t.data_components[:2])
        rule_summary = ", ".join(t.rule_names)
        if len(rule_summary) > 24:
            rule_summary = rule_summary[:21] + "..."
        lines.append(
            f"{t.technique_id:<14} {tech_name:<28} {t.rule_count:<6} "
            f"{t.group_count:<7} {plats:<20} {dcs:<16} {rule_summary}"
        )
    return "\n".join(lines)
