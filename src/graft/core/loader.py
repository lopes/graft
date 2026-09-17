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
    schema_name: str = "secops_custom",
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
        status=str(metadata_raw["status"]),
        priority=str(metadata_raw["priority"])
        if metadata_raw.get("priority") is not None
        else None,
        authors=tuple(str(a) for a in metadata_raw.get("authors", ())),
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
    schema_name: str = "secops_custom",
    validate_mitre: bool = True,
) -> RuleEnvelope:
    file_path = Path(path)
    if not file_path.is_file():
        raise RuleLoadError(f"Rule file not found: {file_path}")
    content = file_path.read_text(encoding="utf-8")
    return load_rule_from_str(content, schema_name=schema_name, validate_mitre=validate_mitre)
