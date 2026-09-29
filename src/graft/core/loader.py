from pathlib import Path
from typing import Any

import yaml

from graft.core.models.rule import (
    BaseDeploymentConfig,
    RuleEnvelope,
    RuleMetadata,
    Runbook,
    TestEvent,
    TestVector,
)
from graft.core.validation.mitre_validator import MitreValidator
from graft.core.validation.schema_validator import SchemaValidator


class RuleLoadError(Exception):
    pass


def load_rule_from_str(
    content: str,
    schema_name: str = "base_rule",
    validate_mitre: bool = True,
) -> RuleEnvelope:
    try:
        data: Any = yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise RuleLoadError(f"YAML parsing error: {e}") from e

    if not isinstance(data, dict):
        raise RuleLoadError("Rule content must be a YAML mapping")

    schema_validator = SchemaValidator()
    errors = schema_validator.validate(data, schema_name=schema_name)
    if errors:
        error_lines = "\n".join(f"- {err.path}: {err.message}" for err in errors)
        raise RuleLoadError(f"Schema validation failed:\n{error_lines}")

    metadata_raw: dict[str, Any] = data.get("metadata", {})
    if validate_mitre and "mitre" in metadata_raw:
        mitre_validator = MitreValidator()
        mitre_errors = mitre_validator.validate(metadata_raw["mitre"])
        if mitre_errors:
            error_lines = "\n".join(f"- {err.tactic}: {err.message}" for err in mitre_errors)
            raise RuleLoadError(f"MITRE validation failed:\n{error_lines}")

    mitre_dict: dict[str, tuple[str, ...]] = {}
    if "mitre" in metadata_raw and isinstance(metadata_raw["mitre"], dict):
        for tactic, techs in metadata_raw["mitre"].items():
            mitre_dict[str(tactic)] = tuple(str(t) for t in techs)

    metadata = RuleMetadata(
        id=str(metadata_raw["id"]),
        name=str(metadata_raw["name"]),
        description=str(metadata_raw["description"]),
        owners=tuple(str(o) for o in metadata_raw.get("owners", ())),
        mitre=mitre_dict,
        tags=tuple(str(t) for t in metadata_raw.get("tags", ())),
        references=tuple(str(r) for r in metadata_raw.get("references", ())),
    )

    deployment_raw: dict[str, Any] = data.get("deployment", {})
    deployment = BaseDeploymentConfig(
        enabled=bool(deployment_raw.get("enabled", True)),
        alerting=bool(deployment_raw.get("alerting", True)),
        run_frequency=str(deployment_raw.get("run_frequency", "unspecified")),
    )

    runbook_raw: dict[str, Any] = data.get("runbook", {})
    runbook = Runbook(
        context=str(runbook_raw.get("context", "")),
        triage=str(runbook_raw.get("triage", "")),
        response=str(runbook_raw.get("response", "")),
    )

    tests_list: list[TestVector] = []
    tests_raw = data.get("tests", [])
    if isinstance(tests_raw, list):
        for t in tests_raw:
            if not isinstance(t, dict):
                continue
            events_list: list[TestEvent] = []
            events_raw = t.get("events", [])
            if isinstance(events_raw, list):
                for ev in events_raw:
                    if not isinstance(ev, dict):
                        continue
                    payload_raw = ev.get("payload", {})
                    payload_dict = payload_raw if isinstance(payload_raw, dict) else {}
                    events_list.append(
                        TestEvent(
                            timestamp=str(ev.get("timestamp", "")),
                            payload=payload_dict,
                        )
                    )
            tests_list.append(
                TestVector(
                    id=str(t["id"]),
                    description=str(t.get("description", "")),
                    expect=int(t.get("expect", 1)),
                    events=tuple(events_list),
                )
            )

    return RuleEnvelope(
        metadata=metadata,
        logic=str(data["logic"]),
        deployment=deployment,
        runbook=runbook,
        tests=tuple(tests_list),
    )


def load_rule_from_yaml(
    path: Path | str,
    schema_name: str | None = None,
    validate_mitre: bool = True,
) -> RuleEnvelope:
    file_path = Path(path)
    if not file_path.is_file():
        raise RuleLoadError(f"Rule file not found: {file_path}")
    content = file_path.read_text(encoding="utf-8")

    if schema_name is None:
        parts = file_path.parts
        for folder in ("rulesets", "rules"):
            if folder in parts:
                idx = parts.index(folder)
                if idx + 1 < len(parts):
                    engine = parts[idx + 1]
                    validator = SchemaValidator()
                    avail = validator.available_schemas()
                    if f"{engine}:rule" in avail:
                        schema_name = f"{engine}:rule"
                    elif f"{engine}_custom" in avail:
                        schema_name = f"{engine}_custom"
                break
        if schema_name is None:
            schema_name = "base_rule"

    return load_rule_from_str(content, schema_name=schema_name, validate_mitre=validate_mitre)


def rule_to_dict(rule: RuleEnvelope) -> dict[str, Any]:
    metadata_dict: dict[str, Any] = {
        "id": rule.metadata.id,
        "name": rule.metadata.name,
        "description": rule.metadata.description,
        "owners": list(rule.metadata.owners),
        "mitre": {k: list(v) for k, v in rule.metadata.mitre.items()},
        "tags": list(rule.metadata.tags),
        "references": list(rule.metadata.references),
    }

    doc: dict[str, Any] = {
        "metadata": metadata_dict,
        "logic": rule.logic,
        "deployment": {
            "enabled": rule.deployment.enabled,
            "alerting": rule.deployment.alerting,
            "run_frequency": rule.deployment.run_frequency,
        },
        "runbook": {
            "context": rule.runbook.context,
            "triage": rule.runbook.triage,
            "response": rule.runbook.response,
        },
        "tests": [
            {
                "id": t.id,
                "description": t.description,
                "expect": t.expect,
                "events": [{"timestamp": ev.timestamp, "payload": ev.payload} for ev in t.events],
            }
            for t in rule.tests
        ],
    }
    return doc


def dump_rule_to_yaml(rule: RuleEnvelope, path: Path | str) -> None:
    doc = rule_to_dict(rule)
    dumped = yaml.safe_dump(doc, sort_keys=False, indent=2)
    dest_path = Path(path)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    dest_path.write_text(dumped, encoding="utf-8")
