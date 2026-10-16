from pathlib import Path

import pytest

from graft.core.mitre_intelligence import (
    build_mitre_coverage_report,
    calculate_mitre_gaps,
    evaluate_technique_coverage_state,
    export_gaps_csv,
    export_gaps_json,
    export_gaps_markdown,
    export_mitre_coverage_csv,
    export_mitre_coverage_json,
    export_mitre_coverage_markdown,
    inspect_mitre_entities,
    render_gaps_table,
    render_inspect_text,
    render_mitre_coverage_table,
    resolve_data_component_id,
    resolve_group_id,
    resolve_platform_name,
    resolve_tactic_shortname,
)
from graft.core.models.rule import (
    BaseDeploymentConfig,
    RuleEnvelope,
    RuleMetadata,
    Runbook,
)


def _make_rule(
    name: str,
    mitre: dict[str, tuple[str, ...]],
    tags: tuple[str, ...] = ("cloud",),
) -> RuleEnvelope:
    return RuleEnvelope(
        metadata=RuleMetadata(
            id="00000000-0000-0000-0000-000000000001",
            name=name,
            description=f"Rule {name}",
            mitre=mitre,
            tags=tags,
        ),
        logic="events: $e condition: $e",
        deployment=BaseDeploymentConfig(enabled=True, alerting=True, run_frequency="live"),
        runbook=Runbook(context="ctx", triage="tr", response="res"),
        tests=(),
    )


def test_resolvers_for_group_platform_data_component_and_tactic() -> None:
    assert resolve_group_id("G0096") == "G0096"
    assert resolve_group_id("apt41") == "G0096"
    assert resolve_group_id("Barium") == "G0096"
    with pytest.raises(ValueError, match="Unknown MITRE threat group"):
        resolve_group_id("G9999_NONEXISTENT")

    assert resolve_platform_name("linux") == "Linux"
    assert resolve_platform_name("iaas") == "IaaS"
    with pytest.raises(ValueError, match="Unknown MITRE platform"):
        resolve_platform_name("Commodore64")

    dc_id = resolve_data_component_id("Command Execution")
    assert dc_id.startswith("DC")
    assert resolve_data_component_id(dc_id) == dc_id
    with pytest.raises(ValueError, match="Unknown MITRE data component"):
        resolve_data_component_id("DC9999_NONEXISTENT")

    assert resolve_tactic_shortname("persistence") == "persistence"
    assert resolve_tactic_shortname("TA0003") == "persistence"
    with pytest.raises(ValueError, match="Unknown MITRE tactic"):
        resolve_tactic_shortname("invalid-tactic-slug")


def test_evaluate_technique_coverage_state_three_state_rollup() -> None:
    covered_ids = {"T1098.001", "T1566"}
    all_techniques = {"T1098", "T1098.001", "T1098.004", "T1566", "T1566.001", "T1059"}

    assert evaluate_technique_coverage_state("T1098.001", covered_ids, all_techniques) == "covered"
    assert evaluate_technique_coverage_state("T1098", covered_ids, all_techniques) == "partial"
    assert (
        evaluate_technique_coverage_state("T1098.004", covered_ids, all_techniques) == "uncovered"
    )
    assert evaluate_technique_coverage_state("T1566", covered_ids, all_techniques) == "covered"
    assert evaluate_technique_coverage_state("T1566.001", covered_ids, all_techniques) == "partial"
    assert evaluate_technique_coverage_state("T1059", covered_ids, all_techniques) == "uncovered"


def test_build_mitre_coverage_report_and_filters() -> None:
    r_aws = _make_rule(
        "aws_iam_access_key_created",
        {"persistence": ("T1098.001",)},
        tags=("aws", "iam"),
    )
    r_gcp = _make_rule(
        "gcp_storage_bucket_public_access_granted",
        {"initial-access": ("T1078.004",)},
        tags=("gcp", "storage"),
    )
    rules = [
        (
            r_aws,
            "siem_alpha",
            Path("rulesets/siem_alpha/custom/aws_iam_access_key_created.yaml"),
            "enabled",
        ),
        (
            r_gcp,
            "siem_alpha",
            Path("rulesets/siem_alpha/custom/gcp_storage_bucket_public_access_granted.yaml"),
            "enabled",
        ),
    ]

    full_report = build_mitre_coverage_report(rules, enrich=True)
    assert full_report.total_rules == 2
    assert full_report.covered_techniques == 2
    assert "aws" in full_report.active_tags
    assert "gcp" in full_report.active_tags

    # Filter by tag
    aws_only = build_mitre_coverage_report(rules, tag="aws", enrich=True)
    assert aws_only.total_rules == 1
    assert [t.technique_id for t in aws_only.techniques] == ["T1098.001"]
    assert len(aws_only.techniques[0].platforms) >= 1
    assert len(aws_only.techniques[0].detection_strategies) >= 1

    # Filter by technique
    tech_only = build_mitre_coverage_report(rules, technique="T1078.004")
    assert [t.technique_id for t in tech_only.techniques] == ["T1078.004"]

    # Renderers
    table_str = render_mitre_coverage_table(full_report, enrich=True)
    assert "T1098.001" in table_str
    assert "aws_iam_access_key_created" in table_str

    json_payload = export_mitre_coverage_json(full_report, enrich=True)
    assert json_payload["covered_techniques"] == 2
    assert "active_tags" in json_payload

    csv_str = export_mitre_coverage_csv(full_report, enrich=True)
    assert "T1098.001" in csv_str

    md_str = export_mitre_coverage_markdown(full_report, enrich=True)
    assert "`T1098.001`" in md_str


def test_calculate_mitre_gaps_rollup_and_prevalence_ranking() -> None:
    r_aws = _make_rule(
        "aws_iam_access_key_created",
        {"persistence": ("T1098.001",)},
        tags=("aws", "iam"),
    )
    rules = [(r_aws, "siem_alpha", None, "enabled")]

    gaps_report = calculate_mitre_gaps(
        rules,
        platform="IaaS",
        tactic="persistence",
        top=10,
    )
    assert gaps_report.scope["platform"] == "IaaS"
    assert gaps_report.scope["tactic"] == "persistence"
    assert len(gaps_report.gaps) <= 10

    # Verify sorted descending by group_count
    counts = [g.group_count for g in gaps_report.gaps]
    assert counts == sorted(counts, reverse=True)

    # T1098.001 is covered so it must not be in gaps; parent T1098 is partial
    gap_ids = {
        g.technique_id: g.coverage_state for g in calculate_mitre_gaps(rules, platform="IaaS").gaps
    }
    assert "T1098.001" not in gap_ids
    assert gap_ids.get("T1098") == "partial"

    assert "T1098" in render_gaps_table(gaps_report) or len(gaps_report.gaps) >= 1
    assert export_gaps_json(gaps_report)["total_gaps"] >= 1
    assert "technique_id" in export_gaps_csv(gaps_report)
    assert "Technique" in export_gaps_markdown(gaps_report)


def test_inspect_mitre_entities_compact_and_expanded() -> None:
    r_aws = _make_rule(
        "aws_iam_access_key_created",
        {"persistence": ("T1098.001",)},
        tags=("aws", "iam"),
    )
    rules = [(r_aws, "siem_alpha", None, "enabled")]

    # 1. Compact technique inspection (default)
    compact_items = inspect_mitre_entities(["T1098.001"], rules=rules)
    assert len(compact_items) == 1
    t_item = compact_items[0]
    assert t_item["id"] == "T1098.001"
    assert t_item["entity_type"] == "technique"
    assert t_item["status"] == "active"
    assert t_item["coverage_state"] == "covered"
    assert "aws_iam_access_key_created" in t_item["local_rules"]
    assert "analytics" not in t_item

    # 2. Expanded technique inspection with --analytics and --platform
    expanded_items = inspect_mitre_entities(
        ["T1098.001"],
        rules=rules,
        include_analytics=True,
        platform="IaaS",
    )
    assert "analytics" in expanded_items[0]
    assert len(expanded_items[0]["analytics"]) >= 1
    for an in expanded_items[0]["analytics"]:
        assert "IaaS" in an["platforms"]

    # 3. Revoked technique inspection
    revoked_items = inspect_mitre_entities(["T1086"])
    assert revoked_items[0]["status"] == "revoked"
    assert revoked_items[0]["revoked_by"] == "T1059.001"

    # 4. Detection Strategy & Analytic inspection
    det_id = t_item["detection_strategies"][0]["id"]
    det_items = inspect_mitre_entities([det_id])
    assert det_items[0]["entity_type"] == "detection_strategy"
    assert len(det_items[0]["analytics"]) >= 1

    an_id = det_items[0]["analytics"][0]["id"]
    an_items = inspect_mitre_entities([an_id])
    assert an_items[0]["entity_type"] == "analytic"
    assert "log_sources" in an_items[0]

    # 5. Threat Group inspection by alias ("APT41" -> G0096)
    group_items = inspect_mitre_entities(["APT41"], rules=rules)
    assert group_items[0]["entity_type"] == "group"
    assert group_items[0]["id"] == "G0096"
    assert "technique_count" in group_items[0]

    # 6. Text rendering
    text_out = render_inspect_text(expanded_items)
    assert "T1098.001" in text_out

    with pytest.raises(ValueError, match="Unknown MITRE entity"):
        inspect_mitre_entities(["NONEXISTENT_ID_999"])
