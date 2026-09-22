import importlib.resources
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from graft.core.models.rule import RuleEnvelope


@dataclass(frozen=True)
class TechniqueCoverage:
    technique_id: str
    technique_name: str
    tactics: list[str]
    rule_count: int
    rule_names: list[str]


@dataclass(frozen=True)
class TechniqueTacticCoverage:
    technique_id: str
    technique_name: str
    tactic_shortname: str
    rule_count: int
    rule_names: list[str]
    engines: list[str]
    statuses: list[str]
    has_runbook: bool
    links: list[dict[str, str]]


@dataclass(frozen=True)
class MatrixCoverageReport:
    total_rules: int
    covered_techniques: int
    techniques: list[TechniqueCoverage]
    tactic_coverages: list[TechniqueTacticCoverage]


def _load_mitre_taxonomy() -> tuple[str, dict[str, dict[str, str]], dict[str, dict[str, Any]]]:
    try:
        resource = importlib.resources.files("graft.data").joinpath("mitre_attack.json")
        content = resource.read_text(encoding="utf-8")
        data: dict[str, Any] = json.loads(content)
        version = str(data.get("version", "19.2"))
        tactics: dict[str, dict[str, str]] = data.get("tactics", {})
        techniques: dict[str, dict[str, Any]] = data.get("techniques", {})
        return version, tactics, techniques
    except (OSError, ValueError, TypeError):
        return "19.2", {}, {}


def calculate_mitre_coverage(
    rules: Sequence[RuleEnvelope | tuple[RuleEnvelope, str, Path | str | None]],
    matrix_data: dict[str, dict[str, Any]] | None = None,
) -> MatrixCoverageReport:
    _version, tactics_db, techniques_db = _load_mitre_taxonomy()
    if matrix_data is not None:
        techniques_db = matrix_data

    # Normalize rules input
    normalized: list[tuple[RuleEnvelope, str, str | None]] = []
    for item in rules:
        if isinstance(item, tuple):
            rule_obj = item[0]
            engine_name = str(item[1]) if len(item) > 1 else "custom"
            path_val = str(item[2]) if len(item) > 2 and item[2] is not None else None
            normalized.append((rule_obj, engine_name, path_val))
        else:
            normalized.append((item, "custom", None))

    tech_rules_map: dict[str, set[str]] = {}
    tech_tactics_map: dict[str, set[str]] = {}

    # (technique_id, tactic_shortname) -> metadata collectors
    pair_map: dict[tuple[str, str], dict[str, Any]] = {}

    for rule, engine, path in normalized:
        rule_name = rule.metadata.name
        status = "enabled" if rule.deployment.enabled else "disabled"
        has_runbook = bool(
            rule.runbook.context.strip()
            or rule.runbook.triage.strip()
            or rule.runbook.response.strip()
        )

        for tactic_slug, tech_list in rule.metadata.mitre.items():
            tactic_info = tactics_db.get(tactic_slug, {})
            shortname = tactic_info.get("shortname", tactic_slug.replace("_", "-"))

            for tech_id in tech_list:
                tech_rules_map.setdefault(tech_id, set()).add(rule_name)
                tech_tactics_map.setdefault(tech_id, set()).add(tactic_slug)

                pair_key = (tech_id, shortname)
                if pair_key not in pair_map:
                    pair_map[pair_key] = {
                        "rules": [],
                        "engines": set(),
                        "statuses": set(),
                        "has_runbook": False,
                        "links": [],
                    }
                if rule_name not in pair_map[pair_key]["rules"]:
                    pair_map[pair_key]["rules"].append(rule_name)
                pair_map[pair_key]["engines"].add(engine)
                pair_map[pair_key]["statuses"].add(status)
                if has_runbook:
                    pair_map[pair_key]["has_runbook"] = True
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

        coverage_list.append(
            TechniqueCoverage(
                technique_id=tech_id,
                technique_name=tech_name,
                tactics=tactics,
                rule_count=len(rule_names),
                rule_names=rule_names,
            )
        )

    tactic_coverage_list: list[TechniqueTacticCoverage] = []
    for (tech_id, shortname), details in sorted(pair_map.items()):
        tech_meta = techniques_db.get(tech_id, {})
        tech_name = str(tech_meta.get("name", "Unknown Technique"))
        tactic_coverage_list.append(
            TechniqueTacticCoverage(
                technique_id=tech_id,
                technique_name=tech_name,
                tactic_shortname=shortname,
                rule_count=len(details["rules"]),
                rule_names=details["rules"],
                engines=sorted(details["engines"]),
                statuses=sorted(details["statuses"]),
                has_runbook=details["has_runbook"],
                links=details["links"],
            )
        )

    return MatrixCoverageReport(
        total_rules=len(normalized),
        covered_techniques=len(coverage_list),
        techniques=coverage_list,
        tactic_coverages=tactic_coverage_list,
    )


def export_navigator_layer(
    report: MatrixCoverageReport,
    layer_name: str = "Graft Detection Coverage",
    color: str = "#008744",
    attack_version: str = "19.2",
) -> dict[str, Any]:
    max_score = max((t.rule_count for t in report.techniques), default=1)

    techniques_payload: list[dict[str, Any]] = []

    # Use tactic-scoped coverage if available
    sources = report.tactic_coverages if report.tactic_coverages else []

    if sources:
        for t in sources:
            if t.tactic_shortname == "none":
                continue
            comment = (
                f"Covered by {t.rule_count} rule(s): {', '.join(t.rule_names)}"
                if t.rule_count > 1
                else f"Rule: {t.rule_names[0]}"
            )
            metadata = [
                {"name": "engine", "value": ", ".join(t.engines)},
                {"name": "rules", "value": ", ".join(t.rule_names)},
                {"name": "status", "value": ", ".join(t.statuses)},
                {"name": "runbook", "value": "yes" if t.has_runbook else "no"},
            ]
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
            techniques_payload.append(
                {
                    "techniqueID": tc.technique_id,
                    "score": tc.rule_count,
                    "color": "",
                    "comment": comment,
                    "enabled": True,
                    "metadata": [],
                    "links": [],
                    "showSubtechniques": True,
                }
            )

    return {
        "name": layer_name,
        "versions": {
            "attack": attack_version,
            "navigator": "5.2.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            f"Graft Detection Coverage Matrix Layer "
            f"({report.total_rules} rules, {report.covered_techniques} techniques)."
        ),
        "filters": {
            "platforms": [
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
        },
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


def render_matrix_table(report: MatrixCoverageReport) -> str:
    summary_header = (
        f"MITRE ATT&CK Detection Matrix "
        f"(Total Rules: {report.total_rules} | Covered Techniques: {report.covered_techniques})"
    )
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
