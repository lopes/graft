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
    render_catalog_table,
    resolve_mitre_attack_pairs,
    resolve_rule_deployment_status,
)
from graft.core.models.rule import (
    BaseDeploymentConfig,
    RuleEnvelope,
    RuleMetadata,
    Runbook,
)


def test_resolve_mitre_attack_pairs() -> None:
    mitre_data = {
        "initial-access": ("T1566.002",),
        "stealth": ("T1055.011",),
    }
    pairs = resolve_mitre_attack_pairs(mitre_data)
    assert pairs == ("TA0001:T1566.002", "TA0005:T1055.011")


def test_resolve_mitre_attack_pairs_unmapped() -> None:
    pairs = resolve_mitre_attack_pairs({"none": ("T0000",)})
    assert pairs == ("TA0000:T0000",)


def test_resolve_rule_deployment_status_fallback() -> None:
    meta = RuleMetadata(id="00000000-0000-0000-0000-000000000001", name="r1", description="d")
    runbook = Runbook(context="c", triage="t", response="r")

    r_enabled = RuleEnvelope(
        metadata=meta,
        logic="events: $e condition: $e",
        deployment=BaseDeploymentConfig(enabled=True, alerting=True),
        runbook=runbook,
        tests=(),
    )
    r_disabled = RuleEnvelope(
        metadata=meta,
        logic="events: $e condition: $e",
        deployment=BaseDeploymentConfig(enabled=False, alerting=False),
        runbook=runbook,
        tests=(),
    )

    assert resolve_rule_deployment_status(r_enabled) == "enabled"
    assert resolve_rule_deployment_status(r_disabled) == "disabled"


def test_build_catalog_entry_from_rule() -> None:
    rule = RuleEnvelope(
        metadata=RuleMetadata(
            id="00000000-0000-0000-0000-000000000001",
            name="workspace_nrd_phishing",
            description="NRD Phishing Test",
            owners=("Joe Lopes", "Detection Engineering"),
            mitre={"initial-access": ("T1566.002",)},
            tags=("workspace", "phishing"),
            references=("https://lopes.id",),
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
    assert entry.status == "enabled"
    assert entry.mitre_attack == ("TA0001:T1566.002",)
    assert entry.tags == ("workspace", "phishing")
    assert entry.owners == ("Joe Lopes", "Detection Engineering")
    assert not hasattr(entry, "author")
    assert entry.created_at == "Unknown"
    assert entry.last_modified_at == "Unknown"
    assert entry.review_count == 0
    assert entry.contributor_count == 0
    assert entry.has_runbook is True


def test_build_catalog_entry_with_git(tmp_path: Path) -> None:
    rule_file = tmp_path / "rule.yaml"
    rule_file.touch()

    rule = RuleEnvelope(
        metadata=RuleMetadata(
            id="00000000-0000-0000-0000-000000000002",
            name="rule_with_git",
            description="Rule with git description",
            owners=("Cloud Security Operations",),
            mitre={},
            tags=(),
        ),
        logic="events: $e condition: $e",
        deployment=BaseDeploymentConfig(enabled=True, alerting=False, run_frequency="hourly"),
        runbook=Runbook(context="", triage="", response=""),
        tests=(),
    )

    mock_git = RuleGitMetadata(
        path=rule_file,
        created_at="2026-02-01",
        last_modified_at="2026-09-20",
        commit_count=7,
        contributor_count=3,
    )

    with patch("graft.core.catalog.extract_git_metadata", return_value=mock_git):
        entry = build_catalog_entry_from_rule(rule=rule, engine="secops", path=rule_file)

    assert entry.owners == ("Cloud Security Operations",)
    assert entry.created_at == "2026-02-01"
    assert entry.last_modified_at == "2026-09-20"
    assert entry.review_count == 7
    assert entry.contributor_count == 3
    assert entry.has_runbook is False


def test_build_catalog_entry_from_registered_managed_rule() -> None:
    from unittest.mock import MagicMock

    from graft.core.models.managed import ManagedState
    from graft.core.models.rule import ManagedRuleRef

    rule = RuleEnvelope(
        metadata=RuleMetadata(
            id="00000000-0000-0000-0000-000000000010",
            name="gcti_active_breach_network_indicators",
            description="Registers GCTI Active Breach Network Indicators ruleset.",
            owners=("Security Operations",),
            mitre={"command-and-control": ("T1071.001",)},
            tags=("secops", "managed"),
            references=(
                "https://docs.cloud.google.com/chronicle/docs/detection/curated-detections",
            ),
        ),
        logic="",
        deployment=BaseDeploymentConfig(enabled=False, alerting=False),
        runbook=Runbook(context="ctx", triage="tr", response="res"),
        tests=(),
        managed=ManagedRuleRef(id="433faf9e-4d51-f284-c35b-009528ecff05"),
    )

    mock_adapter = MagicMock()
    mock_adapter.resolve_deployment_status.return_value = "silent"
    mock_state = ManagedState(rulesets=(), exclusions=())

    entry = build_catalog_entry_from_rule(
        rule=rule,
        engine="secops",
        adapter=mock_adapter,
        managed_state=mock_state,
    )
    assert entry.name == "gcti_active_breach_network_indicators"
    assert entry.rule_type == "managed"
    assert entry.status == "silent"
    mock_adapter.resolve_deployment_status.assert_called_once_with(rule, managed_state=mock_state)


def test_render_catalog_table() -> None:
    entry = CatalogEntry(
        id="00000000-0000-0000-0000-000000000001",
        name="workspace_nrd_phishing",
        engine="secops",
        rule_type="custom",
        status="enabled",
        description="A test rule",
        mitre_attack=("TA0001:T1566.002",),
        tags=("workspace",),
        owners=("Joe Lopes",),
        created_at="2026-01-01",
        last_modified_at="2026-09-22",
        review_count=4,
        contributor_count=2,
        has_runbook=True,
    )

    table = render_catalog_table([entry])
    assert "Rule Name" in table
    assert "Engine" in table
    assert "Type" in table
    assert "Status" in table
    assert "MITRE ATT&CK" in table
    assert "Reviews" in table
    assert "Runbook" in table
    assert "Updated" in table
    assert "workspace_nrd_phishing" in table
    assert "secops" in table
    assert "custom" in table
    assert "enabled" in table
    assert "TA0001:T1566.002" in table


def test_export_catalog_markdown() -> None:
    entry = CatalogEntry(
        id="00000000-0000-0000-0000-000000000001",
        name="test_rule",
        engine="secops",
        rule_type="custom",
        status="enabled",
        description="A test rule",
        mitre_attack=("TA0001:T1566.002",),
        tags=("workspace",),
        owners=("Joe Lopes", "SecOps Team"),
        created_at="2026-01-01",
        last_modified_at="2026-09-22",
        review_count=4,
        contributor_count=2,
        has_runbook=True,
    )

    md = export_catalog_markdown([entry])
    assert "| Rule Name | Engine | Type | Status | MITRE ATT&CK | Owners |" in md
    assert (
        "| `test_rule` | secops | custom | enabled | TA0001:T1566.002 | Joe Lopes, SecOps Team |"
        in md
    )
    assert "| Reviews | Contributors | Runbook |" in md
    assert "| 4 | 2 | yes |" in md


def test_export_catalog_csv() -> None:
    entry = CatalogEntry(
        id="00000000-0000-0000-0000-000000000001",
        name="test_rule",
        engine="secops",
        rule_type="custom",
        status="enabled",
        description="A test rule",
        mitre_attack=("TA0001:T1566.002",),
        tags=("workspace", "phishing"),
        owners=("Joe Lopes", "SecOps Team"),
        created_at="2026-01-01",
        last_modified_at="2026-09-22",
        review_count=4,
        contributor_count=2,
        has_runbook=True,
    )

    csv_output = export_catalog_csv([entry])
    reader = csv.DictReader(io.StringIO(csv_output))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["name"] == "test_rule"
    assert rows[0]["engine"] == "secops"
    assert rows[0]["status"] == "enabled"
    assert rows[0]["mitre_attack"] == "TA0001:T1566.002"
    assert rows[0]["tags"] == "workspace;phishing"
    assert rows[0]["owners"] == "Joe Lopes;SecOps Team"
    assert "author" not in rows[0]
    assert rows[0]["created_at"] == "2026-01-01"
    assert rows[0]["last_modified_at"] == "2026-09-22"
    assert rows[0]["review_count"] == "4"
    assert rows[0]["contributor_count"] == "2"
    assert rows[0]["has_runbook"] == "True"
    assert "severity" not in rows[0]
    assert "has_tests" not in rows[0]


def test_export_catalog_json() -> None:
    entry = CatalogEntry(
        id="00000000-0000-0000-0000-000000000001",
        name="test_rule",
        engine="secops",
        rule_type="custom",
        status="enabled",
        description="A test rule",
        mitre_attack=("TA0001:T1566.002",),
        tags=("workspace",),
        owners=("Joe Lopes", "SecOps Team"),
        created_at="2026-01-01",
        last_modified_at="2026-09-22",
        review_count=4,
        contributor_count=2,
        has_runbook=True,
    )

    payload = export_catalog_json([entry])
    assert len(payload) == 1
    assert payload[0]["name"] == "test_rule"
    assert payload[0]["engine"] == "secops"
    assert payload[0]["status"] == "enabled"
    assert payload[0]["mitre_attack"] == ["TA0001:T1566.002"]
    assert payload[0]["owners"] == ["Joe Lopes", "SecOps Team"]
    assert "author" not in payload[0]
    assert payload[0]["created_at"] == "2026-01-01"
    assert payload[0]["last_modified_at"] == "2026-09-22"
    assert payload[0]["review_count"] == 4
    assert payload[0]["contributor_count"] == 2
    assert payload[0]["has_runbook"] is True
    assert "severity" not in payload[0]
    assert "has_tests" not in payload[0]
