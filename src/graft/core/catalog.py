import csv
import functools
import importlib.resources
import io
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from graft.core.blame import extract_git_metadata
from graft.core.models.rule import RuleEnvelope
from graft.core.ports.engine import EngineAdapter


@dataclass(frozen=True)
class CatalogEntry:
    id: str
    name: str
    engine: str
    rule_type: str
    status: str
    description: str
    mitre_attack: tuple[str, ...]
    tags: tuple[str, ...]
    author: str
    created_at: str
    last_modified_at: str
    review_count: int
    contributor_count: int
    has_runbook: bool


@functools.cache
def _get_tactic_id_map() -> dict[str, str]:
    resource = importlib.resources.files("graft.data").joinpath("mitre_attack.json")
    data: dict[str, Any] = json.loads(resource.read_text(encoding="utf-8"))
    tactics: dict[str, dict[str, str]] = data.get("tactics", {})
    return {slug: info.get("id", slug.upper()) for slug, info in tactics.items()}


def resolve_mitre_attack_pairs(
    mitre: Mapping[str, Sequence[str]],
) -> tuple[str, ...]:
    tactic_map = _get_tactic_id_map()
    pairs: list[str] = []
    for slug, techniques in mitre.items():
        ta_id = tactic_map.get(slug, slug.upper())
        for tech in techniques:
            pairs.append(f"{ta_id}:{tech}")
    return tuple(sorted(set(pairs)))


def resolve_rule_deployment_status(
    rule: RuleEnvelope,
    engine: str | None = None,
    adapter: EngineAdapter | None = None,
) -> str:
    if adapter is not None and hasattr(adapter, "resolve_deployment_status"):
        return adapter.resolve_deployment_status(rule)
    return "enabled" if rule.deployment.enabled else "disabled"


def build_catalog_entry_from_rule(
    rule: RuleEnvelope,
    engine: str,
    path: Path | str | None = None,
    adapter: EngineAdapter | None = None,
    status: str | None = None,
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

    resolved_status = status or resolve_rule_deployment_status(rule, engine, adapter)
    mitre_attack = resolve_mitre_attack_pairs(rule.metadata.mitre)
    has_runbook = bool(
        rule.runbook.context.strip() or rule.runbook.triage.strip() or rule.runbook.response.strip()
    )

    return CatalogEntry(
        id=rule.metadata.id,
        name=rule.metadata.name,
        engine=engine,
        rule_type="custom",
        status=resolved_status,
        description=rule.metadata.description,
        mitre_attack=mitre_attack,
        tags=rule.metadata.tags,
        author=author,
        created_at=created_at,
        last_modified_at=last_modified_at,
        review_count=review_count,
        contributor_count=contributor_count,
        has_runbook=has_runbook,
    )


def render_catalog_table(entries: Sequence[CatalogEntry]) -> str:
    if not entries:
        return "No rules found in catalog."

    headers = [
        "Rule Name",
        "Engine",
        "Status",
        "MITRE ATT&CK",
        "Reviews",
        "Runbook",
        "Updated",
    ]
    rows: list[list[str]] = []
    for e in entries:
        mitre_str = ", ".join(e.mitre_attack) if e.mitre_attack else "-"
        rows.append(
            [
                e.name,
                e.engine,
                e.status,
                mitre_str,
                str(e.review_count),
                "yes" if e.has_runbook else "no",
                e.last_modified_at if e.last_modified_at != "Unknown" else "-",
            ]
        )

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(cell))

    header_line = "  ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    separator_line = "  ".join("-" * col_widths[i] for i in range(len(headers)))
    lines = [header_line, separator_line]

    for row in rows:
        line = "  ".join(row[i].ljust(col_widths[i]) for i in range(len(row)))
        lines.append(line)

    return "\n".join(lines)


def export_catalog_markdown(entries: Sequence[CatalogEntry]) -> str:
    headers = [
        "Rule Name",
        "Engine",
        "Status",
        "MITRE ATT&CK",
        "Author",
        "Created",
        "Last Updated",
        "Reviews",
        "Contributors",
        "Runbook",
    ]
    lines: list[str] = [
        f"| {' | '.join(headers)} |",
        f"| {' | '.join(['---'] * len(headers))} |",
    ]

    for e in entries:
        mitre_str = ", ".join(e.mitre_attack) if e.mitre_attack else "-"
        row = [
            f"`{e.name}`",
            e.engine,
            e.status,
            mitre_str,
            e.author,
            e.created_at if e.created_at != "Unknown" else "-",
            e.last_modified_at if e.last_modified_at != "Unknown" else "-",
            str(e.review_count),
            str(e.contributor_count),
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
        "status",
        "description",
        "mitre_attack",
        "tags",
        "author",
        "created_at",
        "last_modified_at",
        "review_count",
        "contributor_count",
        "has_runbook",
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for e in entries:
        row = asdict(e)
        row["mitre_attack"] = ";".join(e.mitre_attack)
        row["tags"] = ";".join(e.tags)
        writer.writerow(row)

    return output.getvalue()


def export_catalog_json(entries: Sequence[CatalogEntry]) -> list[dict[str, Any]]:
    payload: list[dict[str, Any]] = []
    for e in entries:
        d = asdict(e)
        d["mitre_attack"] = list(e.mitre_attack)
        d["tags"] = list(e.tags)
        payload.append(d)
    return payload
