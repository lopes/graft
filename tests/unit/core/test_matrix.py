from pathlib import Path

from graft.core.matrix import (
    calculate_mitre_coverage,
    export_navigator_layer,
    render_matrix_table,
)
from graft.core.models.rule import (
    BaseDeploymentConfig,
    RuleEnvelope,
    RuleMetadata,
    Runbook,
)


def make_dummy_rule(name: str, mitre: dict[str, tuple[str, ...]]) -> RuleEnvelope:
    return RuleEnvelope(
        metadata=RuleMetadata(
            id="00000000-0000-0000-0000-000000000001",
            name=name,
            description="Test rule",
            mitre=mitre,
        ),
        logic="events: $e condition: $e",
        deployment=BaseDeploymentConfig(enabled=True, alerting=True, run_frequency="live"),
        runbook=Runbook(context="ctx", triage="tr", response="res"),
        tests=(),
    )


def test_calculate_mitre_coverage_aggregation() -> None:
    rule1 = make_dummy_rule("rule_one", {"initial-access": ("T1566.002",)})
    rule2 = make_dummy_rule(
        "rule_two", {"initial-access": ("T1566.002",), "persistence": ("T1098.001",)}
    )
    rule3 = make_dummy_rule("rule_three", {"persistence": ("T1098.001",)})

    report = calculate_mitre_coverage([rule1, rule2, rule3])

    assert report.total_rules == 3
    assert report.covered_techniques == 2

    tech_map = {t.technique_id: t for t in report.techniques}
    assert "T1566.002" in tech_map
    assert tech_map["T1566.002"].rule_count == 2
    assert tech_map["T1566.002"].rule_names == ["rule_one", "rule_two"]

    assert "T1098.001" in tech_map
    assert tech_map["T1098.001"].rule_count == 2
    assert sorted(tech_map["T1098.001"].rule_names) == ["rule_three", "rule_two"]


def test_export_navigator_layer_structure() -> None:
    rule = make_dummy_rule("rule_gcp", {"persistence": ("T1098.001",)})
    report = calculate_mitre_coverage(
        [(rule, "secops", Path("rulesets/secops/custom/rule_gcp.yaml"))]
    )
    layer = export_navigator_layer(report, layer_name="Test Layer")

    assert layer["name"] == "Test Layer"
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["attack"] == "19.2"
    assert layer["versions"]["navigator"] == "5.2.0"
    assert layer["versions"]["layer"] == "4.5"
    assert layer["selectTechniquesAcrossTactics"] is False
    assert layer["gradient"]["colors"] == ["#ffffff", "#008744"]

    assert len(layer["techniques"]) == 1
    t0 = layer["techniques"][0]
    assert t0["techniqueID"] == "T1098.001"
    assert t0["tactic"] == "persistence"
    assert t0["score"] == 1
    assert "rule_gcp" in t0["comment"]

    meta_names = [m["name"] for m in t0["metadata"]]
    assert "engine" in meta_names
    assert "type" in meta_names
    assert "rules" in meta_names
    assert "status" in meta_names
    assert "runbook" not in meta_names

    assert len(t0["links"]) == 1
    assert "rulesets/secops/custom/rule_gcp.yaml" in t0["links"][0]["url"]


def test_export_navigator_layer_custom_color() -> None:
    rule = make_dummy_rule("rule_gcp", {"persistence": ("T1098.001",)})
    report = calculate_mitre_coverage([rule])
    layer = export_navigator_layer(report, layer_name="Custom Color Layer", color="#2e7d32")
    assert layer["gradient"]["colors"] == ["#ffffff", "#2e7d32"]


def test_render_matrix_table() -> None:
    rule = make_dummy_rule("rule_gcp", {"persistence": ("T1098.001",)})
    report = calculate_mitre_coverage([rule])
    table = render_matrix_table(report)

    assert "T1098.001" in table
    assert "rule_gcp" in table
    assert "Covered Techniques: 1" in table or "Total Rules: 1" in table


def test_export_navigator_layer_silent_status() -> None:
    silent_rule = RuleEnvelope(
        metadata=RuleMetadata(
            id="00000000-0000-0000-0000-000000000009",
            name="silent_rule",
            description="Silent mode rule",
            mitre={"persistence": ("T1098.001",)},
        ),
        logic="events: $e condition: $e",
        deployment=BaseDeploymentConfig(enabled=True, alerting=False, run_frequency="live"),
        runbook=Runbook(context="ctx", triage="tr", response="res"),
        tests=(),
    )
    report = calculate_mitre_coverage(
        [(silent_rule, "secops", Path("rulesets/secops/custom/silent_rule.yaml"))]
    )
    layer = export_navigator_layer(report)
    t0 = layer["techniques"][0]
    status_meta = next(m for m in t0["metadata"] if m["name"] == "status")
    assert status_meta["value"] == "silent"


def test_export_navigator_layer_managed_rule_type_and_explicit_status() -> None:
    from graft.core.models.rule import ManagedRuleRef

    managed_rule = RuleEnvelope(
        metadata=RuleMetadata(
            id="00000000-0000-0000-0000-000000000010",
            name="gcti_breach_network_indicator_matched",
            description="Managed GCTI ruleset",
            mitre={"command-and-control": ("T1071.001",)},
        ),
        logic="",
        deployment=BaseDeploymentConfig(enabled=False, alerting=False),
        runbook=Runbook(context="ctx", triage="tr", response="res"),
        tests=(),
        managed=ManagedRuleRef(id="433faf9e-4d51-f284-c35b-009528ecff05"),
    )
    report = calculate_mitre_coverage(
        [
            (
                managed_rule,
                "secops",
                Path("rulesets/secops/managed/gcti_breach_network_indicator_matched.yaml"),
                "silent",
            )
        ]
    )
    layer = export_navigator_layer(report)
    t0 = layer["techniques"][0]
    type_meta = next(m for m in t0["metadata"] if m["name"] == "type")
    status_meta = next(m for m in t0["metadata"] if m["name"] == "status")
    assert type_meta["value"] == "managed"
    assert status_meta["value"] == "silent"

    fallback_report = calculate_mitre_coverage([managed_rule])
    assert fallback_report.tactic_coverages[0].statuses == ["disabled"]
