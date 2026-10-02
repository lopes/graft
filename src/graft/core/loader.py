import re
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml

from graft.core.models.dataset import DatasetEnvelope, DatasetMetadata
from graft.core.models.rule import (
    BaseDeploymentConfig,
    ManagedRuleRef,
    RuleEnvelope,
    RuleMetadata,
    Runbook,
    TestEvent,
    TestVector,
)
from graft.core.validation.mitre_validator import MitreValidator
from graft.core.validation.schema_validator import SchemaValidator

RULE_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)*$")
DATASET_IDENTIFIER_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
DATASET_TTL_COMMENT_PATTERN = re.compile(r"(?<!\S)ttl:(\S*)")
DATASET_TTL_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MAX_RULE_IDENTIFIER_LEN = 64
MAX_DATASET_RAW_LINE_LEN = 512


class RuleLoadError(Exception):
    pass


class DatasetLoadError(Exception):
    pass


def validate_rule_identifier(name: str, kind: str = "rule filename") -> None:
    if name == "index":
        raise RuleLoadError(f"Invalid {kind} '{name}': 'index' is reserved for managed/index.yaml")
    if not (1 <= len(name) <= MAX_RULE_IDENTIFIER_LEN) or not RULE_IDENTIFIER_PATTERN.match(name):
        raise RuleLoadError(
            f"Invalid {kind} '{name}': must be 1..{MAX_RULE_IDENTIFIER_LEN} chars matching "
            f"{RULE_IDENTIFIER_PATTERN.pattern} (lowercase alphanumeric and single underscores, "
            "never starting or ending with underscores)"
        )


def validate_dataset_identifier(name: str, kind: str = "dataset filename") -> None:
    if name == "index":
        raise DatasetLoadError(f"Invalid {kind} '{name}': 'index' is reserved")
    if not (1 <= len(name) <= MAX_RULE_IDENTIFIER_LEN) or not DATASET_IDENTIFIER_PATTERN.match(
        name
    ):
        raise DatasetLoadError(
            f"Invalid {kind} '{name}': must be 1..{MAX_RULE_IDENTIFIER_LEN} chars matching "
            f"{DATASET_IDENTIFIER_PATTERN.pattern} (must start with a lowercase letter, "
            "lowercase alphanumeric and single underscores, never ending with underscores)"
        )


def load_rule_from_str(
    content: str,
    schema_name: str = "base_custom",
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

    managed_raw = data.get("managed")
    managed_ref: ManagedRuleRef | None = None
    if isinstance(managed_raw, dict) and "id" in managed_raw:
        managed_ref = ManagedRuleRef(id=str(managed_raw["id"]))
        logic_str = ""
        deployment = BaseDeploymentConfig(
            enabled=False,
            alerting=False,
            run_frequency="unspecified",
        )
    else:
        logic_str = str(data.get("logic", ""))
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
        logic=logic_str,
        deployment=deployment,
        runbook=runbook,
        tests=tuple(tests_list),
        managed=managed_ref,
    )


def load_rule_from_yaml(
    path: Path | str,
    schema_name: str | None = None,
    validate_mitre: bool = True,
) -> RuleEnvelope:
    file_path = Path(path)
    if not file_path.is_file():
        raise RuleLoadError(f"Rule file not found: {file_path}")
    validate_rule_identifier(file_path.stem, kind="rule filename")
    content = file_path.read_text(encoding="utf-8")

    if schema_name is None:
        parts = file_path.parts
        is_managed_dir = "managed" in parts
        for folder in ("rulesets", "rules"):
            if folder in parts:
                idx = parts.index(folder)
                if idx + 1 < len(parts):
                    engine = parts[idx + 1]
                    if idx + 2 < len(parts) and parts[idx + 2] == "managed":
                        is_managed_dir = True
                    validator = SchemaValidator()
                    avail = validator.available_schemas()
                    if is_managed_dir:
                        schema_name = "base_managed"
                    else:
                        if f"{engine}:custom" in avail:
                            schema_name = f"{engine}:custom"
                        elif f"{engine}_custom" in avail:
                            schema_name = f"{engine}_custom"
                break
        if schema_name is None:
            schema_name = "base_managed" if is_managed_dir else "base_custom"

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
    }
    if rule.managed is not None:
        doc["managed"] = {
            "id": rule.managed.id,
        }
    else:
        doc["logic"] = rule.logic
        doc["deployment"] = {
            "enabled": rule.deployment.enabled,
            "alerting": rule.deployment.alerting,
            "run_frequency": rule.deployment.run_frequency,
        }

    doc["runbook"] = {
        "context": rule.runbook.context,
        "triage": rule.runbook.triage,
        "response": rule.runbook.response,
    }
    doc["tests"] = [
        {
            "id": t.id,
            "description": t.description,
            "expect": t.expect,
            "events": [{"timestamp": ev.timestamp, "payload": ev.payload} for ev in t.events],
        }
        for t in rule.tests
    ]
    return doc


def dump_rule_to_yaml(rule: RuleEnvelope, path: Path | str) -> None:
    doc = rule_to_dict(rule)
    dumped = yaml.safe_dump(doc, sort_keys=False, indent=2)
    dest_path = Path(path)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    dest_path.write_text(dumped, encoding="utf-8")


def _extract_active_dataset_values(
    content: str,
    raw_lines: list[str],
    fallback_values: tuple[str, ...],
    effective_date: date,
) -> tuple[str, ...]:
    root_node = yaml.compose(content)
    if not isinstance(root_node, yaml.MappingNode):
        return fallback_values

    values_node: yaml.SequenceNode | None = None
    for key_node, val_node in root_node.value:
        if isinstance(key_node, yaml.ScalarNode) and key_node.value == "values":
            if isinstance(val_node, yaml.SequenceNode):
                values_node = val_node
            break

    if values_node is None:
        return fallback_values

    active_values: list[str] = []
    for item_node in values_node.value:
        if not isinstance(item_node, yaml.ScalarNode):
            continue
        val_str = str(item_node.value)
        end_line_idx = item_node.end_mark.line
        line_no = end_line_idx + 1
        if 0 <= end_line_idx < len(raw_lines):
            trailing = raw_lines[end_line_idx][item_node.end_mark.column :]
            if "#" in trailing:
                comment_text = trailing.split("#", 1)[1]
                ttl_matches = DATASET_TTL_COMMENT_PATTERN.findall(comment_text)
                if len(ttl_matches) > 1:
                    raise DatasetLoadError(
                        f"Line {line_no}: multiple 'ttl:' directives found in comment"
                    )
                if len(ttl_matches) == 1:
                    ttl_raw = ttl_matches[0]
                    if not DATASET_TTL_DATE_PATTERN.match(ttl_raw):
                        raise DatasetLoadError(
                            f"Line {line_no}: invalid 'ttl:{ttl_raw}' directive "
                            "(expected YYYY-MM-DD calendar date)"
                        )
                    try:
                        ttl_date = date.fromisoformat(ttl_raw)
                    except ValueError as exc:
                        raise DatasetLoadError(
                            f"Line {line_no}: invalid 'ttl:{ttl_raw}' calendar date: {exc}"
                        ) from exc
                    if effective_date > ttl_date:
                        continue
        active_values.append(val_str)

    return tuple(active_values)


def load_dataset_from_str(
    content: str,
    schema_name: str = "base_dataset",
    reference_date: date | None = None,
) -> DatasetEnvelope:
    raw_lines = content.splitlines()
    for line_no, raw_line in enumerate(raw_lines, start=1):
        if len(raw_line) > MAX_DATASET_RAW_LINE_LEN:
            raise DatasetLoadError(
                f"Line {line_no} length ({len(raw_line)} chars) exceeds maximum length "
                f"of {MAX_DATASET_RAW_LINE_LEN} chars"
            )

    try:
        data: Any = yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise DatasetLoadError(f"YAML parsing error: {e}") from e

    if not isinstance(data, dict):
        raise DatasetLoadError("Dataset content must be a YAML mapping")

    schema_validator = SchemaValidator()
    errors = schema_validator.validate(data, schema_name=schema_name)
    if errors:
        error_lines = "\n".join(f"- {err.path}: {err.message}" for err in errors)
        raise DatasetLoadError(f"Schema validation failed:\n{error_lines}")

    metadata_raw: dict[str, Any] = data.get("metadata", {})
    name_str = str(metadata_raw["name"])
    validate_dataset_identifier(name_str, kind="dataset metadata.name")

    metadata = DatasetMetadata(
        name=name_str,
        description=str(metadata_raw["description"]),
        owners=tuple(str(o) for o in metadata_raw.get("owners", ())),
        tags=tuple(str(t) for t in metadata_raw.get("tags", ())),
        references=tuple(str(r) for r in metadata_raw.get("references", ())),
    )

    values_raw = data.get("values", ())
    fallback_values = tuple(str(v) for v in values_raw)
    effective_date = reference_date if reference_date is not None else datetime.now(UTC).date()
    values = _extract_active_dataset_values(
        content=content,
        raw_lines=raw_lines,
        fallback_values=fallback_values,
        effective_date=effective_date,
    )

    return DatasetEnvelope(
        metadata=metadata,
        values=values,
    )


def load_dataset_from_yaml(
    path: Path | str,
    schema_name: str = "base_dataset",
    reference_date: date | None = None,
) -> DatasetEnvelope:
    file_path = Path(path)
    if not file_path.is_file():
        raise DatasetLoadError(f"Dataset file not found: {file_path}")
    validate_dataset_identifier(file_path.stem, kind="dataset filename")
    content = file_path.read_text(encoding="utf-8")
    dataset = load_dataset_from_str(
        content,
        schema_name=schema_name,
        reference_date=reference_date,
    )
    if dataset.metadata.name != file_path.stem:
        raise DatasetLoadError(
            f"Dataset metadata.name '{dataset.metadata.name}' must match "
            f"filename stem '{file_path.stem}'"
        )
    return dataset


def dataset_to_dict(dataset: DatasetEnvelope) -> dict[str, Any]:
    return {
        "metadata": {
            "name": dataset.metadata.name,
            "description": dataset.metadata.description,
            "owners": list(dataset.metadata.owners),
            "tags": list(dataset.metadata.tags),
            "references": list(dataset.metadata.references),
        },
        "values": list(dataset.values),
    }


def dump_dataset_to_yaml(dataset: DatasetEnvelope, path: Path | str) -> None:
    doc = dataset_to_dict(dataset)
    dumped = yaml.safe_dump(doc, sort_keys=False, indent=2)
    dest_path = Path(path)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    dest_path.write_text(dumped, encoding="utf-8")
