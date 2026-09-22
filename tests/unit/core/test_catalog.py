import csv
import io
from pathlib import Path
from unittest.mock import patch

from graft.core.blame import RuleGitMetadata
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
    TestEvent,
    TestVector,
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
    assert entry.created_at == "Unknown"
    assert entry.last_modified_at == "Unknown"
    assert entry.review_count == 0
    assert entry.contributor_count == 0
    assert entry.has_tests is False
    assert entry.test_event_count == 0
    assert entry.has_runbook is True


def test_build_catalog_entry_with_git_and_tests(tmp_path: Path) -> None:
    rule_file = tmp_path / "rule.yaml"
    rule_file.touch()

    rule = RuleEnvelope(
        metadata=RuleMetadata(
            id="00000000-0000-0000-0000-000000000002",
            name="rule_with_tests",
            description="Rule with tests description",
            priority="medium",
            authors=(),
            mitre={},
            tags=(),
        ),
        logic="events: $e condition: $e",
        deployment=BaseDeploymentConfig(enabled=True, alerting=False, run_frequency="hourly"),
        runbook=Runbook(context="", triage="", response=""),
        tests=(
            TestVector(
                id="vec1",
                description="t1",
                expect=1,
                events=(
                    TestEvent(timestamp="2026-01-01T00:00:00Z"),
                    TestEvent(timestamp="2026-01-01T00:01:00Z"),
                ),
            ),
            TestVector(
                id="vec2",
                description="t2",
                expect=0,
                events=(TestEvent(timestamp="2026-01-01T00:02:00Z"),),
            ),
        ),
    )

    mock_git = RuleGitMetadata(
        path=rule_file,
        author="Alice Author",
        created_at="2026-02-01",
        last_modified_by="Bob Committer",
        last_modified_at="2026-09-20",
        commit_count=7,
        contributor_count=3,
    )

    with patch("graft.core.catalog.extract_git_metadata", return_value=mock_git):
        entry = build_catalog_entry_from_rule(rule=rule, engine="secops", path=rule_file)

    assert entry.author == "Alice Author"
    assert entry.created_at == "2026-02-01"
    assert entry.last_modified_at == "2026-09-20"
    assert entry.review_count == 7
    assert entry.contributor_count == 3
    assert entry.has_tests is True
    assert entry.test_event_count == 3
    assert entry.has_runbook is False


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
        review_count=4,
        contributor_count=2,
        has_tests=True,
        test_event_count=3,
        has_runbook=True,
        run_frequency="live",
        enabled=True,
        alerting=True,
    )

    md = export_catalog_markdown([entry])
    assert "| Rule Name | Engine |" in md
    assert "| `test_rule` | secops |" in md
    assert "T1566.002" in md
    assert "| Created | Last Updated | Reviews | Contributors | Tests | Runbook |" in md
    assert "| 2026-01-01 | 2026-09-17 | 4 | 2 | yes (3) | yes |" in md


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
        review_count=4,
        contributor_count=2,
        has_tests=True,
        test_event_count=3,
        has_runbook=True,
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
    assert rows[0]["created_at"] == "2026-01-01"
    assert rows[0]["last_modified_at"] == "2026-09-17"
    assert rows[0]["review_count"] == "4"
    assert rows[0]["contributor_count"] == "2"
    assert rows[0]["has_tests"] == "True"
    assert rows[0]["test_event_count"] == "3"
    assert rows[0]["has_runbook"] == "True"


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
        review_count=4,
        contributor_count=2,
        has_tests=True,
        test_event_count=3,
        has_runbook=True,
        run_frequency="live",
        enabled=True,
        alerting=True,
    )

    payload = export_catalog_json([entry])
    assert len(payload) == 1
    assert payload[0]["name"] == "test_rule"
    assert payload[0]["engine"] == "secops"
    assert payload[0]["created_at"] == "2026-01-01"
    assert payload[0]["last_modified_at"] == "2026-09-17"
    assert payload[0]["review_count"] == 4
    assert payload[0]["contributor_count"] == 2
    assert payload[0]["has_tests"] is True
    assert payload[0]["test_event_count"] == 3
    assert payload[0]["has_runbook"] is True
