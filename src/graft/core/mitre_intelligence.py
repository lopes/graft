import csv
import functools
import importlib.resources
import io
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from graft.core.models.rule import RuleEnvelope

RuleInputItem = (
    RuleEnvelope
    | tuple[RuleEnvelope, str, Path | str | None]
    | tuple[RuleEnvelope, str, Path | str | None, str]
)


@dataclass(frozen=True)
class EnrichedTechniqueCoverage:
    technique_id: str
    technique_name: str
    tactics: list[str]
    platforms: list[str]
    rule_count: int
    rule_names: list[str]
    engines: list[str]
    statuses: list[str]
    rule_tags: list[str]
    detection_strategies: list[str] = field(default_factory=list)
    data_components: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    group_count: int = 0


@dataclass(frozen=True)
class MitreCoverageReport:
    version: str
    total_rules: int
    covered_techniques: int
    active_tags: list[str]
    active_platforms: list[str]
    techniques: list[EnrichedTechniqueCoverage]


@dataclass(frozen=True)
class TechniqueGapEntry:
    technique_id: str
    technique_name: str
    coverage_state: str
    tactics: list[str]
    platforms: list[str]
    group_count: int
    sample_groups: list[str]
    detection_strategies: list[str]
    data_components: list[str]
    partial_rules: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class MitreGapReport:
    version: str
    scope: dict[str, str | None]
    total_in_scope: int
    covered_count: int
    partial_count: int
    uncovered_count: int
    gaps: list[TechniqueGapEntry]


@functools.lru_cache(maxsize=1)
def load_mitre_database() -> dict[str, Any]:
    resource = importlib.resources.files("graft.data").joinpath("mitre_attack.json")
    data: dict[str, Any] = json.loads(resource.read_text(encoding="utf-8"))
    return data


@functools.lru_cache(maxsize=1)
def load_mitre_analytics() -> dict[str, Any]:
    try:
        resource = importlib.resources.files("graft.data").joinpath("mitre_analytics.json")
        data: dict[str, Any] = json.loads(resource.read_text(encoding="utf-8"))
        return data
    except (OSError, ValueError, TypeError):
        return {"version": load_mitre_database().get("version", ""), "analytics": {}}


def _normalize_rules(
    rules: Sequence[RuleInputItem],
) -> list[tuple[RuleEnvelope, str, str | None, str]]:
    normalized: list[tuple[RuleEnvelope, str, str | None, str]] = []
    for item in rules:
        if isinstance(item, tuple):
            rule_obj = item[0]
            engine_name = str(item[1]) if len(item) > 1 else "custom"
            path_val = str(item[2]) if len(item) > 2 and item[2] is not None else None
            explicit_status = str(item[3]) if len(item) > 3 and item[3] is not None else None
        else:
            rule_obj = item
            engine_name = "custom"
            path_val = None
            explicit_status = None

        if explicit_status is not None:
            status = explicit_status
        elif rule_obj.is_managed or not rule_obj.deployment.enabled:
            status = "disabled"
        elif not rule_obj.deployment.alerting:
            status = "silent"
        else:
            status = "enabled"

        normalized.append((rule_obj, engine_name, path_val, status))
    return normalized


def resolve_group_id(query: str, db: Mapping[str, Any] | None = None) -> str:
    data = db if db is not None else load_mitre_database()
    groups: Mapping[str, Any] = data.get("groups", {})
    cleaned = query.strip()
    upper = cleaned.upper()
    if upper in groups:
        return upper

    lower = cleaned.lower()
    for gid, ginfo in groups.items():
        if not isinstance(ginfo, Mapping):
            continue
        if str(ginfo.get("name", "")).strip().lower() == lower:
            return str(gid)
        aliases = ginfo.get("aliases", [])
        if isinstance(aliases, list):
            for alias in aliases:
                if str(alias).strip().lower() == lower:
                    return str(gid)

    raise ValueError(f"Unknown MITRE threat group '{query}'.")


def resolve_platform_name(query: str, db: Mapping[str, Any] | None = None) -> str:
    data = db if db is not None else load_mitre_database()
    techniques: Mapping[str, Any] = data.get("techniques", {})
    all_platforms: dict[str, str] = {}
    for tinfo in techniques.values():
        if isinstance(tinfo, Mapping):
            plats = tinfo.get("platforms", [])
            if isinstance(plats, list):
                for p in plats:
                    p_str = str(p).strip()
                    if p_str:
                        all_platforms[p_str.lower()] = p_str

    lower = query.strip().lower()
    if lower in all_platforms:
        return all_platforms[lower]

    valid_list = ", ".join(sorted(all_platforms.values()))
    raise ValueError(f"Unknown MITRE platform '{query}'. Valid platforms: {valid_list}")


def resolve_data_component_id(query: str, db: Mapping[str, Any] | None = None) -> str:
    data = db if db is not None else load_mitre_database()
    dcs: Mapping[str, Any] = data.get("data_components", {})
    cleaned = query.strip()
    upper = cleaned.upper()
    if upper in dcs:
        return upper

    lower = cleaned.lower()
    for dc_id, dc_info in dcs.items():
        if isinstance(dc_info, Mapping) and str(dc_info.get("name", "")).strip().lower() == lower:
            return str(dc_id)

    raise ValueError(f"Unknown MITRE data component '{query}'.")


def resolve_tactic_shortname(query: str, db: Mapping[str, Any] | None = None) -> str:
    data = db if db is not None else load_mitre_database()
    tactics: Mapping[str, Any] = data.get("tactics", {})
    cleaned = query.strip()
    lower = cleaned.lower()
    if lower in tactics:
        return lower

    upper = cleaned.upper()
    for slug, info in tactics.items():
        if isinstance(info, Mapping) and str(info.get("id", "")).upper() == upper:
            return str(slug)

    valid_slugs = ", ".join(sorted(k for k in tactics if k != "none"))
    raise ValueError(f"Unknown MITRE tactic '{query}'. Valid tactics: {valid_slugs}")


def filter_technique_ids(
    db: Mapping[str, Any] | None = None,
    *,
    platform: str | None = None,
    group: str | None = None,
    tactic: str | None = None,
    data_component: str | None = None,
    det: str | None = None,
    technique: str | None = None,
) -> set[str]:
    data = db if db is not None else load_mitre_database()
    techniques: Mapping[str, Any] = data.get("techniques", {})

    resolved_platform = resolve_platform_name(platform, data) if platform else None
    resolved_group = resolve_group_id(group, data) if group else None
    resolved_tactic = resolve_tactic_shortname(tactic, data) if tactic else None
    resolved_dc = resolve_data_component_id(data_component, data) if data_component else None
    resolved_det = det.strip().upper() if det else None
    if resolved_det and resolved_det not in data.get("detection_strategies", {}):
        raise ValueError(f"Unknown MITRE detection strategy '{det}'.")

    resolved_tech = technique.strip().upper() if technique else None
    if resolved_tech and resolved_tech not in techniques:
        raise ValueError(f"Unknown MITRE technique '{technique}'.")

    matched: set[str] = set()
    for tid, tinfo in techniques.items():
        if tid == "T0000" or not isinstance(tinfo, Mapping):
            continue
        if resolved_tech and tid != resolved_tech:
            continue
        if resolved_platform and resolved_platform not in tinfo.get("platforms", []):
            continue
        if resolved_group and resolved_group not in tinfo.get("groups", []):
            continue
        if resolved_tactic and resolved_tactic not in tinfo.get("tactics", []):
            continue
        if resolved_dc and resolved_dc not in tinfo.get("data_components", []):
            continue
        if resolved_det and resolved_det not in tinfo.get("detection_strategies", []):
            continue
        matched.add(str(tid))

    return matched


def evaluate_technique_coverage_state(
    technique_id: str,
    covered_technique_ids: set[str],
    all_technique_ids: set[str] | None = None,
) -> str:
    tid = technique_id.strip().upper()
    if tid in covered_technique_ids:
        return "covered"

    if "." in tid:
        parent_id = tid.split(".", 1)[0]
        if parent_id in covered_technique_ids:
            return "partial"
    else:
        prefix = f"{tid}."
        if any(c.startswith(prefix) for c in covered_technique_ids):
            return "partial"

    return "uncovered"


def enrich_rule_mitre_metadata(
    mitre: Mapping[str, Sequence[str]],
    db: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    data = db if db is not None else load_mitre_database()
    techniques_db: Mapping[str, Any] = data.get("techniques", {})
    platforms: set[str] = set()
    dcs: set[str] = set()
    mitigations: set[str] = set()
    groups: set[str] = set()
    dets: set[str] = set()

    for techs in mitre.values():
        for tid in techs:
            tinfo = techniques_db.get(tid)
            if not isinstance(tinfo, Mapping):
                continue
            for p in tinfo.get("platforms", []):
                platforms.add(str(p))
            for dc in tinfo.get("data_components", []):
                dcs.add(str(dc))
            for m in tinfo.get("mitigations", []):
                mitigations.add(str(m))
            for g in tinfo.get("groups", []):
                groups.add(str(g))
            for d in tinfo.get("detection_strategies", []):
                dets.add(str(d))

    return {
        "platforms": sorted(platforms),
        "data_components": sorted(dcs),
        "mitigations": sorted(mitigations),
        "detection_strategies": sorted(dets),
        "groups": sorted(groups),
        "group_count": len(groups),
    }


def build_mitre_coverage_report(
    rules: Sequence[RuleInputItem],
    *,
    db: Mapping[str, Any] | None = None,
    platform: str | None = None,
    group: str | None = None,
    tactic: str | None = None,
    technique: str | None = None,
    det: str | None = None,
    data_component: str | None = None,
    tag: str | None = None,
    enrich: bool = False,
) -> MitreCoverageReport:
    data = db if db is not None else load_mitre_database()
    techniques_db: Mapping[str, Any] = data.get("techniques", {})
    version = str(data.get("version", ""))

    has_tech_filter = any(
        x is not None for x in (platform, group, tactic, technique, det, data_component)
    )
    allowed_techs = (
        filter_technique_ids(
            data,
            platform=platform,
            group=group,
            tactic=tactic,
            technique=technique,
            det=det,
            data_component=data_component,
        )
        if has_tech_filter
        else None
    )
    resolved_tactic = resolve_tactic_shortname(tactic, data) if tactic else None
    tag_filter = tag.strip().lower() if tag else None

    normalized = _normalize_rules(rules)
    filtered_rules: list[tuple[RuleEnvelope, str, str | None, str]] = []
    active_tags: set[str] = set()
    active_platforms: set[str] = set()

    tech_collectors: dict[str, dict[str, Any]] = {}

    for rule_obj, engine_name, path_val, status in normalized:
        rule_tags_lower = {t.lower() for t in rule_obj.metadata.tags}
        if tag_filter and tag_filter not in rule_tags_lower:
            continue

        matched_rule = False
        for tac_slug, tech_list in rule_obj.metadata.mitre.items():
            if resolved_tactic and tac_slug != resolved_tactic:
                continue
            for tid in tech_list:
                if allowed_techs is not None and tid not in allowed_techs:
                    continue
                matched_rule = True
                col = tech_collectors.setdefault(
                    tid,
                    {
                        "rules": set(),
                        "tactics": set(),
                        "engines": set(),
                        "statuses": set(),
                        "tags": set(),
                    },
                )
                col["rules"].add(rule_obj.metadata.name)
                col["tactics"].add(tac_slug)
                col["engines"].add(engine_name)
                col["statuses"].add(status)
                for rt in rule_obj.metadata.tags:
                    col["tags"].add(rt)

        if matched_rule or not has_tech_filter:
            filtered_rules.append((rule_obj, engine_name, path_val, status))
            for rt in rule_obj.metadata.tags:
                active_tags.add(rt)

    coverage_items: list[EnrichedTechniqueCoverage] = []
    for tid in sorted(tech_collectors.keys()):
        col = tech_collectors[tid]
        tinfo = techniques_db.get(tid, {})
        if not isinstance(tinfo, Mapping):
            tinfo = {}
        t_name = str(tinfo.get("name", "Unknown Technique"))
        t_tactics_raw = tinfo.get("tactics", [])
        t_tactics = (
            [str(t) for t in t_tactics_raw]
            if isinstance(t_tactics_raw, list) and t_tactics_raw
            else sorted(col["tactics"])
        )
        t_platforms = [str(p) for p in tinfo.get("platforms", [])]
        for p in t_platforms:
            active_platforms.add(p)

        dets = [str(d) for d in tinfo.get("detection_strategies", [])] if enrich else []
        dcs = [str(dc) for dc in tinfo.get("data_components", [])] if enrich else []
        mits = [str(m) for m in tinfo.get("mitigations", [])] if enrich else []
        g_list = tinfo.get("groups", [])
        g_count = len(g_list) if isinstance(g_list, list) else 0

        coverage_items.append(
            EnrichedTechniqueCoverage(
                technique_id=tid,
                technique_name=t_name,
                tactics=t_tactics,
                platforms=t_platforms,
                rule_count=len(col["rules"]),
                rule_names=sorted(col["rules"]),
                engines=sorted(col["engines"]),
                statuses=sorted(col["statuses"]),
                rule_tags=sorted(col["tags"]),
                detection_strategies=dets,
                data_components=dcs,
                mitigations=mits,
                group_count=g_count,
            )
        )

    return MitreCoverageReport(
        version=version,
        total_rules=len(filtered_rules),
        covered_techniques=len(coverage_items),
        active_tags=sorted(active_tags),
        active_platforms=sorted(active_platforms),
        techniques=coverage_items,
    )


def render_mitre_coverage_table(report: MitreCoverageReport, enrich: bool = False) -> str:
    header = (
        f"MITRE ATT&CK v{report.version} Coverage "
        f"(Total Rules: {report.total_rules} | Covered Techniques: {report.covered_techniques})"
    )
    if not enrich:
        lines = [
            header,
            "=" * 96,
            (
                f"{'Technique ID':<14} {'Technique Name':<30} {'Rules':<6} "
                f"{'Platforms':<20} {'Rules / Detections'}"
            ),
            "-" * 96,
        ]
        for t in report.techniques:
            t_name = (
                t.technique_name[:28] + ".." if len(t.technique_name) > 30 else t.technique_name
            )
            plats = ", ".join(t.platforms)
            if len(plats) > 18:
                plats = plats[:16] + ".."
            r_sum = ", ".join(t.rule_names)
            if len(r_sum) > 30:
                r_sum = r_sum[:27] + "..."
            lines.append(f"{t.technique_id:<14} {t_name:<30} {t.rule_count:<6} {plats:<20} {r_sum}")
        return "\n".join(lines)

    lines = [
        header,
        "=" * 118,
        (
            f"{'Technique ID':<13} {'Technique Name':<26} {'Rules':<5} {'Groups':<6} "
            f"{'Strategies':<12} {'Data Components':<18} {'Rules / Detections'}"
        ),
        "-" * 118,
    ]
    for t in report.techniques:
        t_name = t.technique_name[:24] + ".." if len(t.technique_name) > 26 else t.technique_name
        dets = ",".join(t.detection_strategies[:2])
        dcs = ",".join(t.data_components[:2])
        r_sum = ", ".join(t.rule_names)
        if len(r_sum) > 28:
            r_sum = r_sum[:25] + "..."
        lines.append(
            f"{t.technique_id:<13} {t_name:<26} {t.rule_count:<5} "
            f"{t.group_count:<6} {dets:<12} {dcs:<18} {r_sum}"
        )
    return "\n".join(lines)


def export_mitre_coverage_json(report: MitreCoverageReport, enrich: bool = False) -> dict[str, Any]:
    techs_out: list[dict[str, Any]] = []
    for t in report.techniques:
        item: dict[str, Any] = {
            "technique_id": t.technique_id,
            "technique_name": t.technique_name,
            "tactics": t.tactics,
            "platforms": t.platforms,
            "rule_count": t.rule_count,
            "rule_names": t.rule_names,
            "engines": t.engines,
            "statuses": t.statuses,
            "rule_tags": t.rule_tags,
        }
        if enrich:
            item["detection_strategies"] = t.detection_strategies
            item["data_components"] = t.data_components
            item["mitigations"] = t.mitigations
            item["group_count"] = t.group_count
        techs_out.append(item)

    return {
        "success": True,
        "version": report.version,
        "total_rules": report.total_rules,
        "covered_techniques": report.covered_techniques,
        "active_tags": report.active_tags,
        "active_platforms": report.active_platforms,
        "techniques": techs_out,
    }


def export_mitre_coverage_csv(report: MitreCoverageReport, enrich: bool = False) -> str:
    fieldnames = [
        "technique_id",
        "technique_name",
        "tactics",
        "platforms",
        "rule_count",
        "rule_names",
        "engines",
        "statuses",
        "rule_tags",
    ]
    if enrich:
        fieldnames.extend(["detection_strategies", "data_components", "mitigations", "group_count"])

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for t in report.techniques:
        row: dict[str, Any] = {
            "technique_id": t.technique_id,
            "technique_name": t.technique_name,
            "tactics": ";".join(t.tactics),
            "platforms": ";".join(t.platforms),
            "rule_count": t.rule_count,
            "rule_names": ";".join(t.rule_names),
            "engines": ";".join(t.engines),
            "statuses": ";".join(t.statuses),
            "rule_tags": ";".join(t.rule_tags),
        }
        if enrich:
            row["detection_strategies"] = ";".join(t.detection_strategies)
            row["data_components"] = ";".join(t.data_components)
            row["mitigations"] = ";".join(t.mitigations)
            row["group_count"] = t.group_count
        writer.writerow(row)
    return buf.getvalue().rstrip("\n")


def export_mitre_coverage_markdown(report: MitreCoverageReport, enrich: bool = False) -> str:
    headers = ["Technique ID", "Technique Name", "Tactics", "Platforms", "Rules", "Rule Names"]
    if enrich:
        headers.extend(["Groups", "Strategies", "Data Components", "Mitigations"])

    lines = [
        f"| {' | '.join(headers)} |",
        f"| {' | '.join(['---'] * len(headers))} |",
    ]
    for t in report.techniques:
        row = [
            f"`{t.technique_id}`",
            t.technique_name,
            ", ".join(t.tactics),
            ", ".join(t.platforms),
            str(t.rule_count),
            ", ".join(f"`{r}`" for r in t.rule_names),
        ]
        if enrich:
            row.extend(
                [
                    str(t.group_count),
                    ", ".join(t.detection_strategies) or "-",
                    ", ".join(t.data_components) or "-",
                    ", ".join(t.mitigations) or "-",
                ]
            )
        lines.append(f"| {' | '.join(row)} |")
    return "\n".join(lines)


def calculate_mitre_gaps(
    rules: Sequence[RuleInputItem],
    *,
    db: Mapping[str, Any] | None = None,
    platform: str | None = None,
    group: str | None = None,
    tactic: str | None = None,
    data_component: str | None = None,
    top: int | None = None,
) -> MitreGapReport:
    data = db if db is not None else load_mitre_database()
    techniques_db: Mapping[str, Any] = data.get("techniques", {})
    groups_db: Mapping[str, Any] = data.get("groups", {})
    version = str(data.get("version", ""))

    resolved_platform = resolve_platform_name(platform, data) if platform else None
    resolved_group = resolve_group_id(group, data) if group else None
    resolved_tactic = resolve_tactic_shortname(tactic, data) if tactic else None
    resolved_dc = resolve_data_component_id(data_component, data) if data_component else None

    in_scope_ids = filter_technique_ids(
        data,
        platform=resolved_platform,
        group=resolved_group,
        tactic=resolved_tactic,
        data_component=resolved_dc,
    )

    normalized = _normalize_rules(rules)
    covered_ids: set[str] = set()
    tech_to_rules: dict[str, set[str]] = {}
    for rule_obj, _, _, _ in normalized:
        for techs in rule_obj.metadata.mitre.values():
            for tid in techs:
                covered_ids.add(tid)
                tech_to_rules.setdefault(tid, set()).add(rule_obj.metadata.name)

    all_tech_ids = set(techniques_db.keys())
    covered_count = 0
    partial_count = 0
    uncovered_count = 0
    gap_entries: list[TechniqueGapEntry] = []

    for tid in sorted(in_scope_ids):
        state = evaluate_technique_coverage_state(tid, covered_ids, all_tech_ids)
        if state == "covered":
            covered_count += 1
            continue
        if state == "partial":
            partial_count += 1
        else:
            uncovered_count += 1

        tinfo = techniques_db.get(tid, {})
        if not isinstance(tinfo, Mapping):
            continue
        g_ids = [str(g) for g in tinfo.get("groups", [])]
        sample_groups: list[str] = []
        for gid in g_ids[:3]:
            g_obj = groups_db.get(gid, {})
            g_name = str(g_obj.get("name", gid)) if isinstance(g_obj, Mapping) else gid
            sample_groups.append(f"{gid} ({g_name})")

        partial_rules: set[str] = set()
        if state == "partial":
            if "." in tid:
                parent_id = tid.split(".", 1)[0]
                partial_rules.update(tech_to_rules.get(parent_id, set()))
            else:
                prefix = f"{tid}."
                for c_id, r_names in tech_to_rules.items():
                    if c_id.startswith(prefix):
                        partial_rules.update(r_names)

        gap_entries.append(
            TechniqueGapEntry(
                technique_id=tid,
                technique_name=str(tinfo.get("name", "")),
                coverage_state=state,
                tactics=[str(t) for t in tinfo.get("tactics", [])],
                platforms=[str(p) for p in tinfo.get("platforms", [])],
                group_count=len(g_ids),
                sample_groups=sample_groups,
                detection_strategies=[str(d) for d in tinfo.get("detection_strategies", [])],
                data_components=[str(dc) for dc in tinfo.get("data_components", [])],
                partial_rules=sorted(partial_rules),
            )
        )

    gap_entries.sort(
        key=lambda g: (-g.group_count, 0 if g.coverage_state == "uncovered" else 1, g.technique_id)
    )
    if top is not None and top >= 0:
        gap_entries = gap_entries[:top]

    return MitreGapReport(
        version=version,
        scope={
            "platform": resolved_platform,
            "group": resolved_group,
            "tactic": resolved_tactic,
            "data_component": resolved_dc,
        },
        total_in_scope=len(in_scope_ids),
        covered_count=covered_count,
        partial_count=partial_count,
        uncovered_count=uncovered_count,
        gaps=gap_entries,
    )


def render_gaps_table(report: MitreGapReport) -> str:
    active_filters = [f"{k}={v}" for k, v in report.scope.items() if v is not None]
    scope_str = ", ".join(active_filters) if active_filters else "all enterprise-attack"
    header = (
        f"MITRE ATT&CK v{report.version} Gap Analysis [{scope_str}]\n"
        f"In Scope: {report.total_in_scope} | Covered: {report.covered_count} | "
        f"Partial: {report.partial_count} | Uncovered: {report.uncovered_count} "
        f"(Showing {len(report.gaps)} gaps)"
    )
    lines = [
        header,
        "=" * 112,
        (
            f"{'Technique ID':<13} {'State':<10} {'Groups':<7} {'Technique Name':<30} "
            f"{'Strategies':<12} {'Data Components'}"
        ),
        "-" * 112,
    ]
    for g in report.gaps:
        t_name = g.technique_name[:28] + ".." if len(g.technique_name) > 30 else g.technique_name
        dets = ", ".join(g.detection_strategies[:2]) or "-"
        dcs = ", ".join(g.data_components[:3]) or "-"
        lines.append(
            f"{g.technique_id:<13} {g.coverage_state:<10} {g.group_count:<7} "
            f"{t_name:<30} {dets:<12} {dcs}"
        )
    return "\n".join(lines)


def export_gaps_json(report: MitreGapReport) -> dict[str, Any]:
    return {
        "success": True,
        "version": report.version,
        "scope": report.scope,
        "total_in_scope": report.total_in_scope,
        "covered_count": report.covered_count,
        "partial_count": report.partial_count,
        "uncovered_count": report.uncovered_count,
        "total_gaps": len(report.gaps),
        "gaps": [
            {
                "technique_id": g.technique_id,
                "technique_name": g.technique_name,
                "coverage_state": g.coverage_state,
                "tactics": g.tactics,
                "platforms": g.platforms,
                "group_count": g.group_count,
                "sample_groups": g.sample_groups,
                "detection_strategies": g.detection_strategies,
                "data_components": g.data_components,
                "partial_rules": g.partial_rules,
            }
            for g in report.gaps
        ],
    }


def export_gaps_csv(report: MitreGapReport) -> str:
    fieldnames = [
        "technique_id",
        "technique_name",
        "coverage_state",
        "group_count",
        "tactics",
        "platforms",
        "detection_strategies",
        "data_components",
        "partial_rules",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for g in report.gaps:
        writer.writerow(
            {
                "technique_id": g.technique_id,
                "technique_name": g.technique_name,
                "coverage_state": g.coverage_state,
                "group_count": g.group_count,
                "tactics": ";".join(g.tactics),
                "platforms": ";".join(g.platforms),
                "detection_strategies": ";".join(g.detection_strategies),
                "data_components": ";".join(g.data_components),
                "partial_rules": ";".join(g.partial_rules),
            }
        )
    return buf.getvalue().rstrip("\n")


def export_gaps_markdown(report: MitreGapReport) -> str:
    headers = [
        "Technique ID",
        "Technique Name",
        "State",
        "Groups",
        "Tactics",
        "Platforms",
        "Strategies",
        "Data Components",
    ]
    lines = [
        f"| {' | '.join(headers)} |",
        f"| {' | '.join(['---'] * len(headers))} |",
    ]
    for g in report.gaps:
        row = [
            f"`{g.technique_id}`",
            g.technique_name,
            g.coverage_state,
            str(g.group_count),
            ", ".join(g.tactics),
            ", ".join(g.platforms),
            ", ".join(g.detection_strategies) or "-",
            ", ".join(g.data_components) or "-",
        ]
        lines.append(f"| {' | '.join(row)} |")
    return "\n".join(lines)


def inspect_mitre_entities(
    targets: Sequence[str],
    *,
    rules: Sequence[RuleInputItem] = (),
    db: Mapping[str, Any] | None = None,
    analytics_db: Mapping[str, Any] | None = None,
    platform: str | None = None,
    include_analytics: bool = False,
    include_groups: bool = False,
    full: bool = False,
) -> list[dict[str, Any]]:
    data = db if db is not None else load_mitre_database()
    techniques_db: Mapping[str, Any] = data.get("techniques", {})
    inactive_db: Mapping[str, Any] = data.get("inactive_techniques", {})
    groups_db: Mapping[str, Any] = data.get("groups", {})
    mitigations_db: Mapping[str, Any] = data.get("mitigations", {})
    dcs_db: Mapping[str, Any] = data.get("data_components", {})
    dets_db: Mapping[str, Any] = data.get("detection_strategies", {})
    tactics_db: Mapping[str, Any] = data.get("tactics", {})

    resolved_platform = resolve_platform_name(platform, data) if platform else None
    want_analytics = include_analytics or full
    want_groups = include_groups or full

    normalized = _normalize_rules(rules)
    covered_ids: set[str] = set()
    tech_to_rules: dict[str, set[str]] = {}
    for rule_obj, _, _, _ in normalized:
        for techs in rule_obj.metadata.mitre.values():
            for tid in techs:
                covered_ids.add(tid)
                tech_to_rules.setdefault(tid, set()).add(rule_obj.metadata.name)

    all_tech_ids = set(techniques_db.keys())
    results: list[dict[str, Any]] = []

    for raw_target in targets:
        cleaned = raw_target.strip()
        upper = cleaned.upper()
        lower = cleaned.lower()

        # 1. Active Technique
        if upper in techniques_db:
            tinfo = techniques_db[upper]
            if not isinstance(tinfo, Mapping):
                continue
            parent_id = upper.split(".", 1)[0] if "." in upper else None
            subtechniques = (
                sorted(k for k in techniques_db if k.startswith(f"{upper}."))
                if "." not in upper
                else []
            )
            det_ids = [str(d) for d in tinfo.get("detection_strategies", [])]
            det_summaries = [
                {
                    "id": did,
                    "name": str(dets_db.get(did, {}).get("name", "")),
                    "analytics": list(dets_db.get(did, {}).get("analytics", [])),
                }
                for did in det_ids
            ]
            dc_ids = [str(dc) for dc in tinfo.get("data_components", [])]
            dc_summaries = [
                {"id": dcid, "name": str(dcs_db.get(dcid, {}).get("name", ""))} for dcid in dc_ids
            ]
            mit_ids = [str(m) for m in tinfo.get("mitigations", [])]
            mit_summaries = [
                {
                    "id": mid,
                    "name": str(mitigations_db.get(mid, {}).get("name", "")),
                    "description": str(mitigations_db.get(mid, {}).get("description", "")),
                }
                for mid in mit_ids
            ]
            g_ids = [str(g) for g in tinfo.get("groups", [])]
            g_preview_ids = g_ids if want_groups else g_ids[:5]
            g_summaries = [
                {"id": gid, "name": str(groups_db.get(gid, {}).get("name", ""))}
                for gid in g_preview_ids
            ]

            item: dict[str, Any] = {
                "id": upper,
                "entity_type": "technique",
                "name": str(tinfo.get("name", "")),
                "status": "active",
                "tactics": [str(t) for t in tinfo.get("tactics", [])],
                "platforms": [str(p) for p in tinfo.get("platforms", [])],
                "parent_technique": parent_id,
                "subtechniques": subtechniques,
                "coverage_state": evaluate_technique_coverage_state(
                    upper, covered_ids, all_tech_ids
                ),
                "local_rules": sorted(tech_to_rules.get(upper, set())),
                "detection_strategies": det_summaries,
                "data_components": dc_summaries,
                "mitigations": mit_summaries,
                "group_count": len(g_ids),
                "groups": g_summaries,
            }

            if want_analytics:
                an_data = analytics_db if analytics_db is not None else load_mitre_analytics()
                an_map: Mapping[str, Any] = an_data.get("analytics", {})
                an_list: list[dict[str, Any]] = []
                for d_obj in det_summaries:
                    for an_id in d_obj["analytics"]:
                        an_info = an_map.get(an_id)
                        if not isinstance(an_info, Mapping):
                            continue
                        an_plats = [str(p) for p in an_info.get("platforms", [])]
                        if resolved_platform and resolved_platform not in an_plats:
                            continue
                        an_list.append(
                            {
                                "id": an_id,
                                "name": str(an_info.get("name", "")),
                                "strategy_id": str(an_info.get("strategy_id", d_obj["id"])),
                                "platforms": an_plats,
                                "description": str(an_info.get("description", "")),
                                "log_sources": list(an_info.get("log_sources", [])),
                                "mutable_elements": list(an_info.get("mutable_elements", [])),
                            }
                        )
                item["analytics"] = an_list

            results.append(item)
            continue

        # 2. Inactive (Revoked / Deprecated) Technique
        if upper in inactive_db:
            in_info = inactive_db[upper]
            rev_by = in_info.get("revoked_by") if isinstance(in_info, Mapping) else None
            rep_summary: dict[str, Any] | None = None
            if isinstance(rev_by, str) and rev_by in techniques_db:
                rep_obj = techniques_db[rev_by]
                if isinstance(rep_obj, Mapping):
                    rep_summary = {
                        "id": rev_by,
                        "name": str(rep_obj.get("name", "")),
                        "tactics": [str(t) for t in rep_obj.get("tactics", [])],
                        "platforms": [str(p) for p in rep_obj.get("platforms", [])],
                    }
            results.append(
                {
                    "id": upper,
                    "entity_type": "technique",
                    "name": str(in_info.get("name", "")) if isinstance(in_info, Mapping) else "",
                    "status": str(in_info.get("status", "deprecated"))
                    if isinstance(in_info, Mapping)
                    else "deprecated",
                    "revoked_by": rev_by,
                    "replacement": rep_summary,
                }
            )
            continue

        # 3. Detection Strategy (DETxxxx)
        if upper in dets_db:
            d_info = dets_db[upper]
            an_data = analytics_db if analytics_db is not None else load_mitre_analytics()
            an_map = an_data.get("analytics", {})
            an_ids = d_info.get("analytics", []) if isinstance(d_info, Mapping) else []
            an_list = []
            for an_id in an_ids:
                an_info = an_map.get(an_id)
                if not isinstance(an_info, Mapping):
                    continue
                an_plats = [str(p) for p in an_info.get("platforms", [])]
                if resolved_platform and resolved_platform not in an_plats:
                    continue
                an_list.append(
                    {
                        "id": str(an_id),
                        "name": str(an_info.get("name", "")),
                        "platforms": an_plats,
                        "description": str(an_info.get("description", "")),
                        "log_sources": list(an_info.get("log_sources", [])),
                        "mutable_elements": list(an_info.get("mutable_elements", [])),
                    }
                )
            detected_techs = sorted(
                tid
                for tid, t_obj in techniques_db.items()
                if isinstance(t_obj, Mapping) and upper in t_obj.get("detection_strategies", [])
            )
            results.append(
                {
                    "id": upper,
                    "entity_type": "detection_strategy",
                    "name": str(d_info.get("name", "")) if isinstance(d_info, Mapping) else "",
                    "detected_techniques": detected_techs,
                    "analytics": an_list,
                }
            )
            continue

        # 4. Analytic (ANxxxx)
        if upper.startswith("AN"):
            an_data = analytics_db if analytics_db is not None else load_mitre_analytics()
            an_map = an_data.get("analytics", {})
            if upper in an_map and isinstance(an_map[upper], Mapping):
                an_info = an_map[upper]
                results.append(
                    {
                        "id": upper,
                        "entity_type": "analytic",
                        "name": str(an_info.get("name", "")),
                        "strategy_id": str(an_info.get("strategy_id", "")),
                        "platforms": [str(p) for p in an_info.get("platforms", [])],
                        "description": str(an_info.get("description", "")),
                        "log_sources": list(an_info.get("log_sources", [])),
                        "mutable_elements": list(an_info.get("mutable_elements", [])),
                    }
                )
                continue

        # 5. Mitigation (Mxxxx)
        if upper in mitigations_db and isinstance(mitigations_db[upper], Mapping):
            m_info = mitigations_db[upper]
            mitigated_techs = sorted(
                tid
                for tid, t_obj in techniques_db.items()
                if isinstance(t_obj, Mapping) and upper in t_obj.get("mitigations", [])
            )
            results.append(
                {
                    "id": upper,
                    "entity_type": "mitigation",
                    "name": str(m_info.get("name", "")),
                    "description": str(m_info.get("description", "")),
                    "techniques": mitigated_techs,
                }
            )
            continue

        # 6. Data Component (DCxxxx)
        if upper in dcs_db and isinstance(dcs_db[upper], Mapping):
            dc_info = dcs_db[upper]
            dc_techs = sorted(
                tid
                for tid, t_obj in techniques_db.items()
                if isinstance(t_obj, Mapping) and upper in t_obj.get("data_components", [])
            )
            results.append(
                {
                    "id": upper,
                    "entity_type": "data_component",
                    "name": str(dc_info.get("name", "")),
                    "techniques": dc_techs,
                }
            )
            continue

        # 7. Tactic (TAxxxx or shortname)
        if lower in tactics_db or any(
            isinstance(v, Mapping) and str(v.get("id", "")).upper() == upper
            for v in tactics_db.values()
        ):
            slug = resolve_tactic_shortname(cleaned, data)
            tac_info = tactics_db[slug]
            tac_techs = sorted(
                tid
                for tid, t_obj in techniques_db.items()
                if isinstance(t_obj, Mapping) and slug in t_obj.get("tactics", [])
            )
            results.append(
                {
                    "id": str(tac_info.get("id", upper)),
                    "shortname": slug,
                    "entity_type": "tactic",
                    "name": str(tac_info.get("name", "")),
                    "technique_count": len(tac_techs),
                    "techniques": tac_techs,
                }
            )
            continue

        # 8. Threat Group (Gxxxx or alias)
        try:
            gid = resolve_group_id(cleaned, data)
            g_info = groups_db[gid]
            g_techs = sorted(
                tid
                for tid, t_obj in techniques_db.items()
                if isinstance(t_obj, Mapping)
                and gid in t_obj.get("groups", [])
                and (not resolved_platform or resolved_platform in t_obj.get("platforms", []))
            )
            cov_list = [
                tid
                for tid in g_techs
                if evaluate_technique_coverage_state(tid, covered_ids, all_tech_ids) == "covered"
            ]
            part_list = [
                tid
                for tid in g_techs
                if evaluate_technique_coverage_state(tid, covered_ids, all_tech_ids) == "partial"
            ]
            uncov_list = [
                tid
                for tid in g_techs
                if evaluate_technique_coverage_state(tid, covered_ids, all_tech_ids) == "uncovered"
            ]
            results.append(
                {
                    "id": gid,
                    "entity_type": "group",
                    "name": str(g_info.get("name", "")),
                    "aliases": list(g_info.get("aliases", [])),
                    "technique_count": len(g_techs),
                    "covered_techniques": cov_list,
                    "partial_techniques": part_list,
                    "uncovered_techniques": uncov_list,
                }
            )
            continue
        except ValueError:
            pass

        raise ValueError(f"Unknown MITRE entity '{raw_target}'.")

    return results


def render_inspect_text(items: Sequence[Mapping[str, Any]]) -> str:
    blocks: list[str] = []
    for item in items:
        etype = str(item.get("entity_type", ""))
        eid = str(item.get("id", ""))
        ename = str(item.get("name", ""))
        lines = [f"[{etype.upper()}] {eid} — {ename}", "-" * 72]

        if etype == "technique":
            status = str(item.get("status", "active"))
            lines.append(f"Status:            {status}")
            if status != "active":
                rev_by = item.get("revoked_by")
                lines.append(f"Revoked By:        {rev_by or 'None (deprecated)'}")
            else:
                lines.append(f"Tactics:           {', '.join(item.get('tactics', []))}")
                lines.append(f"Platforms:         {', '.join(item.get('platforms', []))}")
                lines.append(
                    f"Coverage State:    {item.get('coverage_state')} "
                    f"(Local Rules: {', '.join(item.get('local_rules', [])) or 'none'})"
                )
                if item.get("subtechniques"):
                    lines.append(f"Sub-techniques:    {', '.join(item.get('subtechniques', []))}")
                dets = [f"{d['id']} ({d['name']})" for d in item.get("detection_strategies", [])]
                dcs = [f"{dc['id']} ({dc['name']})" for dc in item.get("data_components", [])]
                mits = [f"{m['id']} ({m['name']})" for m in item.get("mitigations", [])]
                groups = [f"{g['id']} ({g['name']})" for g in item.get("groups", [])]
                lines.append(f"Strategies:        {'; '.join(dets) or 'none'}")
                lines.append(f"Data Components:   {'; '.join(dcs) or 'none'}")
                lines.append(f"Mitigations:       {'; '.join(mits) or 'none'}")
                lines.append(
                    f"Threat Groups:     {item.get('group_count', 0)} total "
                    f"({', '.join(groups) or 'none'})"
                )
                if "analytics" in item:
                    lines.append("Analytics:")
                    for an in item["analytics"]:
                        lines.append(
                            f"  • {an['id']} [{', '.join(an.get('platforms', []))}]: "
                            f"{an.get('description', '')}"
                        )
                        for ls in an.get("log_sources", []):
                            lines.append(
                                f"      Log Source: {ls.get('name')} ({ls.get('channel')}) "
                                f"[{ls.get('data_component')}]"
                            )
                        for me in an.get("mutable_elements", []):
                            lines.append(
                                f"      Tunable ({me.get('field')}): {me.get('description')}"
                            )
        elif etype == "detection_strategy":
            lines.append(f"Detects:           {', '.join(item.get('detected_techniques', []))}")
            for an in item.get("analytics", []):
                lines.append(
                    f"  • {an['id']} [{', '.join(an.get('platforms', []))}]: "
                    f"{an.get('description', '')}"
                )
        elif etype == "analytic":
            lines.append(f"Strategy:          {item.get('strategy_id')}")
            lines.append(f"Platforms:         {', '.join(item.get('platforms', []))}")
            lines.append(f"Description:       {item.get('description')}")
        elif etype == "group":
            lines.append(f"Aliases:           {', '.join(item.get('aliases', []))}")
            lines.append(f"Techniques Used:   {item.get('technique_count', 0)}")
            lines.append(
                f"Covered:           {', '.join(item.get('covered_techniques', [])) or 'none'}"
            )
            lines.append(
                f"Partial:           {', '.join(item.get('partial_techniques', [])) or 'none'}"
            )
            lines.append(
                f"Uncovered:         {', '.join(item.get('uncovered_techniques', [])) or 'none'}"
            )
        else:
            if "description" in item:
                lines.append(f"Description:       {item.get('description')}")
            if "techniques" in item:
                lines.append(f"Techniques:        {', '.join(item.get('techniques', []))}")

        blocks.append("\n".join(lines))

    return "\n\n".join(blocks)
