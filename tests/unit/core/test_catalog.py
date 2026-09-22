import csv
import io

from graft.core.catalog import (
    CatalogEntry,
    build_catalog_entry_from_rule,
    export_catalog_csv,
    export_catalog_json,
    export_catalog_markdown,
)
from graft.core.models.rule import (
    BaseDeploymentConfig,
    RuleEnvelope,
    RuleMetadata,
    Runbook,
)


def test_build_catalog_entry_from_rule() -> None:
    rule = RuleEnvelope(
        metadata=RuleMetadata(
            id="00000000-0000-0000-0000-000000000001",
            name="workspace_nrd_phishing",
            description="NRD Phishing Test",
            priority="high",
            authors=("Joe Lopes",),
            mitre={"initial_access": ("T1566.002",)},
            tags=("workspace", "phishing"),
        ),
        logic="events: $e condition: $e",
        deployment=BaseDeploymentConfig(enabled=True, alerting=True, run_frequency="live"),
        runbook=Runbook(context="ctx", triage="tr", response="res"),
        tests=(),
    )

    entry = build_catalog_entry_from_rule(rule=rule, engine="secops")
    assert entry.name == "workspace_nrd_phishing"
    assert entry.engine == "secops"
    assert entry.rule_type == "custom"
    assert entry.severity == "high"
    assert "T1566.002" in entry.mitre_techniques
    assert "initial_access" in entry.mitre_tactics
    assert entry.author == "Joe Lopes"
    assert entry.enabled is True
    assert entry.alerting is True
    assert entry.run_frequency == "live"


def test_export_catalog_markdown() -> None:
    entry = CatalogEntry(
        id="00000000-0000-0000-0000-000000000001",
        name="test_rule",
        engine="secops",
        rule_type="custom",
        severity="high",
        description="A test rule",
        mitre_tactics=("initial_access",),
        mitre_techniques=("T1566.002",),
        tags=("workspace",),
        author="Joe Lopes",
        created_at="2026-01-01",
        last_modified_at="2026-09-17",
        run_frequency="live",
        enabled=True,
        alerting=True,
    )

    md = export_catalog_markdown([entry])
    assert "| Rule Name | Engine |" in md
    assert "| `test_rule` | secops |" in md
    assert "T1566.002" in md


def test_export_catalog_csv() -> None:
    entry = CatalogEntry(
        id="00000000-0000-0000-0000-000000000001",
        name="test_rule",
        engine="secops",
        rule_type="custom",
        severity="high",
        description="A test rule",
        mitre_tactics=("initial_access",),
        mitre_techniques=("T1566.002",),
        tags=("workspace",),
        author="Joe Lopes",
        created_at="2026-01-01",
        last_modified_at="2026-09-17",
        run_frequency="live",
        enabled=True,
        alerting=True,
    )

    csv_output = export_catalog_csv([entry])
    reader = csv.DictReader(io.StringIO(csv_output))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["name"] == "test_rule"
    assert rows[0]["engine"] == "secops"
    assert rows[0]["mitre_techniques"] == "T1566.002"


def test_export_catalog_json() -> None:
    entry = CatalogEntry(
        id="00000000-0000-0000-0000-000000000001",
        name="test_rule",
        engine="secops",
        rule_type="custom",
        severity="high",
        description="A test rule",
        mitre_tactics=("initial_access",),
        mitre_techniques=("T1566.002",),
        tags=("workspace",),
        author="Joe Lopes",
        created_at="2026-01-01",
        last_modified_at="2026-09-17",
        run_frequency="live",
        enabled=True,
        alerting=True,
    )

    payload = export_catalog_json([entry])
    assert len(payload) == 1
    assert payload[0]["name"] == "test_rule"
    assert payload[0]["engine"] == "secops"
