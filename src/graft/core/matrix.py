import importlib.resources
import json
from collections.abc import Sequence
from dataclasses import dataclass
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
class MatrixCoverageReport:
    total_rules: int
    covered_techniques: int
    techniques: list[TechniqueCoverage]


def _load_mitre_database() -> dict[str, dict[str, Any]]:
    try:
        resource = importlib.resources.files("graft.data").joinpath("mitre_attack.json")
        content = resource.read_text(encoding="utf-8")
        data: dict[str, Any] = json.loads(content)
        techniques: dict[str, dict[str, Any]] = data.get("techniques", {})
        return techniques
    except (OSError, ValueError, TypeError):
        return {}


def calculate_mitre_coverage(
    rules: Sequence[RuleEnvelope],
    matrix_data: dict[str, dict[str, Any]] | None = None,
) -> MatrixCoverageReport:
    techniques_db = matrix_data if matrix_data is not None else _load_mitre_database()

    # Aggregate rules per technique ID
    tech_rules_map: dict[str, set[str]] = {}
    tech_tactics_map: dict[str, set[str]] = {}

    for rule in rules:
        rule_name = rule.metadata.name
        mitre_mapping = rule.metadata.mitre
        for tactic, tech_list in mitre_mapping.items():
            for tech_id in tech_list:
                tech_rules_map.setdefault(tech_id, set()).add(rule_name)
                tech_tactics_map.setdefault(tech_id, set()).add(tactic)

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

    return MatrixCoverageReport(
        total_rules=len(rules),
        covered_techniques=len(coverage_list),
        techniques=coverage_list,
    )


def export_navigator_layer(
    report: MatrixCoverageReport,
    layer_name: str = "Graft Detection Coverage",
) -> dict[str, Any]:
    max_score = max((t.rule_count for t in report.techniques), default=1)

    techniques_payload: list[dict[str, Any]] = []
    for t in report.techniques:
        comment = f"Covered by {t.rule_count} rule(s): {', '.join(t.rule_names)}"
        techniques_payload.append(
            {
                "techniqueID": t.technique_id,
                "score": t.rule_count,
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
            "attack": "14",
            "navigator": "4.5",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": "Graft Detection Coverage Matrix Layer",
        "filters": {"platforms": ["Linux", "macOS", "Windows", "IaaS", "Google Workspace", "SaaS"]},
        "sorting": 3,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
        },
        "gradient": {
            "colors": ["#ffffff", "#66b2ff", "#0066cc"],
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

    lines.append("-" * 90)
    return "\n".join(lines)
