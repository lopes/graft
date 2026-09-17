import importlib.resources
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MitreValidationError:
    tactic: str
    technique: str | None
    message: str


class MitreValidator:
    def __init__(self, matrix_path: Path | None = None) -> None:
        if matrix_path is not None:
            content = matrix_path.read_text(encoding="utf-8")
        else:
            resource = importlib.resources.files("graft.data").joinpath("mitre_attack.json")
            content = resource.read_text(encoding="utf-8")

        data = json.loads(content)
        self._tactics: dict[str, dict[str, str]] = data.get("tactics", {})
        self._techniques: dict[str, dict[str, object]] = data.get("techniques", {})

    def validate(self, mitre_mappings: Mapping[str, Sequence[str]]) -> list[MitreValidationError]:
        errors: list[MitreValidationError] = []

        for tactic, techniques in mitre_mappings.items():
            if tactic not in self._tactics:
                errors.append(
                    MitreValidationError(
                        tactic=tactic,
                        technique=None,
                        message=f"Unknown MITRE tactic '{tactic}'.",
                    )
                )
                continue

            for tech_id in techniques:
                tech_data = self._techniques.get(tech_id)
                if tech_data is None:
                    errors.append(
                        MitreValidationError(
                            tactic=tactic,
                            technique=tech_id,
                            message=f"Unknown MITRE technique '{tech_id}'.",
                        )
                    )
                    continue

                valid_tactics = tech_data.get("tactics", [])
                if isinstance(valid_tactics, list) and tactic not in valid_tactics:
                    tech_name = str(tech_data.get("name", ""))
                    errors.append(
                        MitreValidationError(
                            tactic=tactic,
                            technique=tech_id,
                            message=(
                                f"Technique '{tech_id}' ({tech_name}) does not belong "
                                f"to tactic '{tactic}'. Valid tactics: {valid_tactics}"
                            ),
                        )
                    )

        return errors

    def is_valid(self, mitre_mappings: Mapping[str, Sequence[str]]) -> bool:
        return len(self.validate(mitre_mappings)) == 0
