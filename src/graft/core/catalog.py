import csv
import io
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from graft.core.blame import extract_git_metadata
from graft.core.models.rule import RuleEnvelope


@dataclass(frozen=True)
class CatalogEntry:
    id: str
    name: str
    engine: str
    rule_type: str
    severity: str | None
    description: str
    mitre_tactics: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    tags: tuple[str, ...]
    author: str
    created_at: str
    last_modified_at: str
    review_count: int
    contributor_count: int
    has_tests: bool
    test_event_count: int
    has_runbook: bool
    run_frequency: str
    enabled: bool
    alerting: bool


def build_catalog_entry_from_rule(
    rule: RuleEnvelope,
    engine: str,
    path: Path | str | None = None,
) -> CatalogEntry:
    author = rule.metadata.authors[0] if rule.metadata.authors else "Unknown"
    created_at = "Unknown"
    last_modified_at = "Unknown"
    review_count = 0
    contributor_count = 0

    if path is not None:
        p = Path(path)
        if p.is_file():
            git_meta = extract_git_metadata(p)
            if git_meta.author != "Unknown":
                author = git_meta.author
            created_at = git_meta.created_at
            last_modified_at = git_meta.last_modified_at
            review_count = git_meta.commit_count
            contributor_count = git_meta.contributor_count

    tactics = sorted(rule.metadata.mitre.keys())
    techniques: list[str] = []
    for tech_list in rule.metadata.mitre.values():
        techniques.extend(tech_list)
    techniques = sorted(set(techniques))

    has_tests = bool(rule.tests)
    test_event_count = sum(len(t.events) for t in rule.tests)
    has_runbook = bool(
        rule.runbook.context.strip() or rule.runbook.triage.strip() or rule.runbook.response.strip()
    )

    return CatalogEntry(
        id=rule.metadata.id,
        name=rule.metadata.name,
        engine=engine,
        rule_type="custom",
        severity=rule.metadata.priority,
        description=rule.metadata.description,
        mitre_tactics=tuple(tactics),
        mitre_techniques=tuple(techniques),
        tags=rule.metadata.tags,
        author=author,
        created_at=created_at,
        last_modified_at=last_modified_at,
        review_count=review_count,
        contributor_count=contributor_count,
        has_tests=has_tests,
        test_event_count=test_event_count,
        has_runbook=has_runbook,
        run_frequency=rule.deployment.run_frequency,
        enabled=rule.deployment.enabled,
        alerting=rule.deployment.alerting,
    )


def export_catalog_markdown(entries: Sequence[CatalogEntry]) -> str:
    headers = [
        "Rule Name",
        "Engine",
        "Type",
        "Enabled",
        "Alerting",
        "Run Frequency",
        "MITRE Techniques",
        "Author",
        "Created",
        "Last Updated",
        "Reviews",
        "Contributors",
        "Tests",
        "Runbook",
    ]
    lines: list[str] = [
        f"| {' | '.join(headers)} |",
        f"| {' | '.join(['---'] * len(headers))} |",
    ]

    for e in entries:
        tech_str = ", ".join(e.mitre_techniques) if e.mitre_techniques else "-"
        row = [
            f"`{e.name}`",
            e.engine,
            e.rule_type,
            "yes" if e.enabled else "no",
            "yes" if e.alerting else "no",
            e.run_frequency,
            tech_str,
            e.author,
            e.created_at if e.created_at != "Unknown" else "-",
            e.last_modified_at if e.last_modified_at != "Unknown" else "-",
            str(e.review_count),
            str(e.contributor_count),
            f"yes ({e.test_event_count})" if e.has_tests else "no",
            "yes" if e.has_runbook else "no",
        ]
        lines.append(f"| {' | '.join(row)} |")

    return "\n".join(lines)


def export_catalog_csv(entries: Sequence[CatalogEntry]) -> str:
    fieldnames = [
        "id",
        "name",
        "engine",
        "rule_type",
        "severity",
        "description",
        "mitre_tactics",
        "mitre_techniques",
        "tags",
        "author",
        "created_at",
        "last_modified_at",
        "review_count",
        "contributor_count",
        "has_tests",
        "test_event_count",
        "has_runbook",
        "run_frequency",
        "enabled",
        "alerting",
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for e in entries:
        row = asdict(e)
        row["mitre_tactics"] = ";".join(e.mitre_tactics)
        row["mitre_techniques"] = ";".join(e.mitre_techniques)
        row["tags"] = ";".join(e.tags)
        writer.writerow(row)

    return output.getvalue()


def export_catalog_json(entries: Sequence[CatalogEntry]) -> list[dict[str, Any]]:
    payload: list[dict[str, Any]] = []
    for e in entries:
        payload.append(asdict(e))
    return payload
