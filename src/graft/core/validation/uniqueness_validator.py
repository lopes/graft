from dataclasses import dataclass
from pathlib import Path

from graft.core.models.rule import RuleEnvelope


@dataclass(frozen=True)
class RuleUniquenessViolation:
    rule_id: str
    rule_name: str
    engine: str
    path: str
    conflicting_path: str
    conflicting_engine: str
    violation_type: str
    message: str


class RuleUniquenessValidator:
    def __init__(self) -> None:
        self._seen_ids: dict[str, tuple[str, str]] = {}
        self._seen_names: dict[tuple[str, str], str] = {}

    def add_and_validate(
        self,
        rule: RuleEnvelope,
        engine: str,
        path: Path | str,
    ) -> list[RuleUniquenessViolation]:
        violations: list[RuleUniquenessViolation] = []
        path_str = str(path)
        rule_id = rule.metadata.id
        rule_name = rule.metadata.name

        if rule_id in self._seen_ids:
            conflicting_engine, conflicting_path = self._seen_ids[rule_id]
            violations.append(
                RuleUniquenessViolation(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    engine=engine,
                    path=path_str,
                    conflicting_path=conflicting_path,
                    conflicting_engine=conflicting_engine,
                    violation_type="id",
                    message=(
                        f"Duplicate rule metadata.id '{rule_id}' in '{path_str}' "
                        f"(engine: '{engine}') conflicts with '{conflicting_path}' "
                        f"(engine: '{conflicting_engine}'). "
                        "Rule IDs must be globally unique across all engines."
                    ),
                )
            )
        else:
            self._seen_ids[rule_id] = (engine, path_str)

        engine_name_key = (engine, rule_name)
        if engine_name_key in self._seen_names:
            conflicting_path = self._seen_names[engine_name_key]
            violations.append(
                RuleUniquenessViolation(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    engine=engine,
                    path=path_str,
                    conflicting_path=conflicting_path,
                    conflicting_engine=engine,
                    violation_type="name",
                    message=(
                        f"Duplicate rule metadata.name '{rule_name}' in engine '{engine}' "
                        f"in '{path_str}' conflicts with '{conflicting_path}'. "
                        f"Rule names must be unique within their engine."
                    ),
                )
            )
        else:
            self._seen_names[engine_name_key] = path_str

        return violations

    def reset(self) -> None:
        self._seen_ids.clear()
        self._seen_names.clear()
