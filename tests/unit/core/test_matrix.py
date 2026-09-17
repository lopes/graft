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
            status="production",
            mitre=mitre,
        ),
        logic="events: $e condition: $e",
        deployment=BaseDeploymentConfig(enabled=True, alerting=True, run_frequency="live"),
        runbook=Runbook(context="ctx", triage="tr", response="res"),
        tests=(),
    )


def test_calculate_mitre_coverage_aggregation() -> None:
    rule1 = make_dummy_rule("rule_one", {"initial_access": ("T1566.002",)})
    rule2 = make_dummy_rule(
        "rule_two", {"initial_access": ("T1566.002",), "persistence": ("T1098.001",)}
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
    assert tech_map["T1098.001"].rule_names == ["rule_three", "rule_two"] or sorted(
        tech_map["T1098.001"].rule_names
    ) == ["rule_three", "rule_two"]


def test_export_navigator_layer_structure() -> None:
    rule = make_dummy_rule("rule_gcp", {"persistence": ("T1098.001",)})
    report = calculate_mitre_coverage([rule])
    layer = export_navigator_layer(report, layer_name="Test Layer")

    assert layer["name"] == "Test Layer"
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["navigator"] == "4.5"
    assert len(layer["techniques"]) == 1
    assert layer["techniques"][0]["techniqueID"] == "T1098.001"
    assert layer["techniques"][0]["score"] == 1
    assert "rule_gcp" in layer["techniques"][0]["comment"]


def test_render_matrix_table() -> None:
    rule = make_dummy_rule("rule_gcp", {"persistence": ("T1098.001",)})
    report = calculate_mitre_coverage([rule])
    table = render_matrix_table(report)

    assert "T1098.001" in table
    assert "rule_gcp" in table
    assert "Covered Techniques: 1" in table or "Total Rules: 1" in table
