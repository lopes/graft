import importlib.resources
import json
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-19.2.json"
)


def parse_attack_stix_bundle(stix_data: dict[str, Any], version: str = "19.2") -> dict[str, Any]:
    tactics: dict[str, dict[str, str]] = {}
    for o in stix_data.get("objects", []):
        if o.get("type") == "x-mitre-tactic" and not o.get("x_mitre_deprecated", False):
            ref = next(
                (
                    r["external_id"]
                    for r in o.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"
                ),
                None,
            )
            shortname = o.get("x_mitre_shortname")
            name = o.get("name")
            if ref and shortname and name:
                slug = str(shortname).replace("-", "_")
                tactics[slug] = {"id": str(ref), "name": str(name), "shortname": str(shortname)}

    tactics["none"] = {"id": "TA0000", "name": "Unmapped / Forwarded Alerts", "shortname": "none"}

    techniques: dict[str, dict[str, Any]] = {}
    for o in stix_data.get("objects", []):
        if (
            o.get("type") == "attack-pattern"
            and not o.get("x_mitre_deprecated", False)
            and not o.get("revoked", False)
        ):
            ref = next(
                (
                    r["external_id"]
                    for r in o.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"
                ),
                None,
            )
            name = o.get("name")
            tech_tactics = [
                p.get("phase_name", "").replace("-", "_")
                for p in o.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ]
            if ref and name:
                techniques[str(ref)] = {
                    "name": str(name),
                    "tactics": sorted(set(str(t) for t in tech_tactics if t)),
                }

    techniques["T0000"] = {"name": "Alert Forwarder / Unmapped Telemetry", "tactics": ["none"]}

    return {
        "version": version,
        "tactics": dict(sorted(tactics.items())),
        "techniques": dict(sorted(techniques.items())),
    }


def update_mitre_taxonomy(
    source_url: str | None = None,
    target_path: Path | None = None,
) -> dict[str, Any]:
    url = source_url or DEFAULT_ATTACK_STIX_URL
    if not (url.startswith("https://") or url.startswith("http://")):
        raise ValueError(
            f"Invalid STIX source URL scheme: {url}. Must start with https:// or http://"
        )

    req = urllib.request.Request(url, headers={"User-Agent": "graft-updater"})  # noqa: S310
    with urllib.request.urlopen(req) as resp:  # noqa: S310
        stix_data: dict[str, Any] = json.loads(resp.read().decode("utf-8"))

    payload = parse_attack_stix_bundle(stix_data)

    if target_path is not None:
        dest = target_path
    else:
        resource = importlib.resources.files("graft.data").joinpath("mitre_attack.json")
        dest = Path(str(resource))

    dest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


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
        self._version: str = str(data.get("version", "19.2"))
        self._tactics: dict[str, dict[str, str]] = data.get("tactics", {})
        self._techniques: dict[str, dict[str, object]] = data.get("techniques", {})

    @property
    def version(self) -> str:
        return self._version

    @property
    def tactics(self) -> dict[str, dict[str, str]]:
        return self._tactics

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
