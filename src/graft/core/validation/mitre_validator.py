import functools
import importlib.resources
import json
import re
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_ATTACK_INDEX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
)
DEFAULT_ATTACK_STIX_BASE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack"
)
DEFAULT_ATTACK_STIX_URL = f"{DEFAULT_ATTACK_STIX_BASE_URL}/enterprise-attack-19.2.json"

_TACTIC_ID_RE = re.compile(r"^TA\d{4}$", re.IGNORECASE)
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_CITATION_RE = re.compile(r"\s*\(Citation:[^)]+\)")
_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]+\)")


def _extract_mitre_external_id(obj: Mapping[str, Any]) -> str | None:
    refs = obj.get("external_references")
    if not isinstance(refs, list):
        return None
    for ref in refs:
        if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
            ext_id = ref.get("external_id")
            if isinstance(ext_id, str) and ext_id.strip():
                return ext_id.strip()
    return None


def _summarize_first_sentence(text: str) -> str:
    cleaned = _CITATION_RE.sub("", text).strip()
    cleaned = _MD_LINK_RE.sub(r"\1", cleaned)
    first_para = cleaned.split("\n", 1)[0].strip()
    if ". " in first_para:
        return first_para.split(". ", 1)[0].strip() + "."
    return first_para


def _detect_bundle_version(stix_data: Mapping[str, Any], fallback: str = "19.2") -> str:
    objects = stix_data.get("objects")
    if isinstance(objects, list):
        for obj in objects:
            if isinstance(obj, dict) and obj.get("type") == "x-mitre-collection":
                ver = obj.get("x_mitre_version")
                if isinstance(ver, str) and ver.strip():
                    return ver.strip()
    return fallback


def _parse_version_tuple(version_str: str) -> tuple[int, ...]:
    parts: list[int] = []
    for token in version_str.strip().lstrip("vV").split("."):
        digits = "".join(ch for ch in token if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def parse_attack_stix_bundle(
    stix_data: dict[str, Any],
    version: str | None = None,
) -> dict[str, Any]:
    if not isinstance(stix_data, dict):
        raise ValueError("STIX bundle must be a JSON object")

    resolved_version = version if version is not None else _detect_bundle_version(stix_data)
    raw_objects = stix_data.get("objects", [])
    objects: list[dict[str, Any]] = (
        [o for o in raw_objects if isinstance(o, dict)] if isinstance(raw_objects, list) else []
    )

    stix_id_to_ext_id: dict[str, str] = {}
    for o in objects:
        stix_id = o.get("id")
        ext_id = _extract_mitre_external_id(o)
        if isinstance(stix_id, str) and ext_id:
            stix_id_to_ext_id[stix_id] = ext_id

    tactics: dict[str, dict[str, str]] = {}
    for o in objects:
        if (
            o.get("type") == "x-mitre-tactic"
            and not o.get("x_mitre_deprecated", False)
            and not o.get("revoked", False)
        ):
            ref = _extract_mitre_external_id(o)
            shortname = o.get("x_mitre_shortname")
            name = o.get("name")
            if ref and shortname and name:
                tactics[str(shortname)] = {"id": str(ref), "name": str(name)}

    tactics["none"] = {"id": "TA0000", "name": "Unmapped / Forwarded Alerts"}
    legacy_tactics: dict[str, dict[str, Any]] = {
        "defense-evasion": {
            "id": "TA0005",
            "replaced_by": ["stealth", "defense-impairment"],
        }
    }

    groups: dict[str, dict[str, Any]] = {}
    for o in objects:
        if (
            o.get("type") == "intrusion-set"
            and not o.get("x_mitre_deprecated", False)
            and not o.get("revoked", False)
        ):
            ref = _extract_mitre_external_id(o)
            name = o.get("name")
            raw_aliases = o.get("aliases", [])
            aliases = (
                sorted({str(a).strip() for a in raw_aliases if str(a).strip()})
                if isinstance(raw_aliases, list)
                else []
            )
            if ref and name:
                groups[ref] = {"name": str(name), "aliases": aliases}

    mitigations: dict[str, dict[str, str]] = {}
    for o in objects:
        if (
            o.get("type") == "course-of-action"
            and not o.get("x_mitre_deprecated", False)
            and not o.get("revoked", False)
        ):
            ref = _extract_mitre_external_id(o)
            name = o.get("name")
            desc = str(o.get("description", ""))
            if ref and name and not ref.startswith("T"):
                mitigations[ref] = {
                    "name": str(name),
                    "description": _summarize_first_sentence(desc),
                }

    data_components: dict[str, dict[str, str]] = {}
    for o in objects:
        if (
            o.get("type") == "x-mitre-data-component"
            and not o.get("x_mitre_deprecated", False)
            and not o.get("revoked", False)
        ):
            ref = _extract_mitre_external_id(o)
            name = o.get("name")
            if ref and name:
                data_components[ref] = {"name": str(name)}

    analytic_stix_to_dcs: dict[str, set[str]] = {}
    for o in objects:
        if (
            o.get("type") == "x-mitre-analytic"
            and not o.get("x_mitre_deprecated", False)
            and not o.get("revoked", False)
        ):
            stix_id = o.get("id")
            if not isinstance(stix_id, str):
                continue
            ls_refs = o.get("x_mitre_log_source_references", [])
            dcs: set[str] = set()
            if isinstance(ls_refs, list):
                for ls in ls_refs:
                    if isinstance(ls, dict):
                        dc_stix = ls.get("x_mitre_data_component_ref")
                        if isinstance(dc_stix, str) and dc_stix in stix_id_to_ext_id:
                            dcs.add(stix_id_to_ext_id[dc_stix])
            analytic_stix_to_dcs[stix_id] = dcs

    detection_strategies: dict[str, dict[str, Any]] = {}
    det_to_dcs: dict[str, set[str]] = {}
    for o in objects:
        if (
            o.get("type") == "x-mitre-detection-strategy"
            and not o.get("x_mitre_deprecated", False)
            and not o.get("revoked", False)
        ):
            ref = _extract_mitre_external_id(o)
            name = o.get("name")
            raw_an_refs = o.get("x_mitre_analytic_refs", [])
            an_ids: list[str] = []
            dcs_for_det: set[str] = set()
            if isinstance(raw_an_refs, list):
                for an_stix in raw_an_refs:
                    if isinstance(an_stix, str):
                        if an_stix in stix_id_to_ext_id:
                            an_ids.append(stix_id_to_ext_id[an_stix])
                        dcs_for_det.update(analytic_stix_to_dcs.get(an_stix, set()))
            if ref and name:
                detection_strategies[ref] = {
                    "name": str(name),
                    "analytics": sorted(set(an_ids)),
                }
                det_to_dcs[ref] = dcs_for_det

    revoked_by_map: dict[str, str] = {}
    tech_groups: dict[str, set[str]] = {}
    tech_mitigations: dict[str, set[str]] = {}
    tech_dets: dict[str, set[str]] = {}

    for o in objects:
        if (
            o.get("type") != "relationship"
            or o.get("x_mitre_deprecated", False)
            or o.get("revoked", False)
        ):
            continue
        rel_type = o.get("relationship_type")
        src_stix = o.get("source_ref")
        tgt_stix = o.get("target_ref")
        if not (isinstance(src_stix, str) and isinstance(tgt_stix, str)):
            continue
        src_ext = stix_id_to_ext_id.get(src_stix)
        tgt_ext = stix_id_to_ext_id.get(tgt_stix)
        if not (src_ext and tgt_ext):
            continue

        if rel_type == "revoked-by" and src_stix.startswith("attack-pattern--"):
            revoked_by_map[src_ext] = tgt_ext
        elif (
            rel_type == "uses"
            and src_stix.startswith("intrusion-set--")
            and tgt_stix.startswith("attack-pattern--")
            and src_ext in groups
        ):
            tech_groups.setdefault(tgt_ext, set()).add(src_ext)
        elif (
            rel_type == "mitigates"
            and src_stix.startswith("course-of-action--")
            and tgt_stix.startswith("attack-pattern--")
            and src_ext in mitigations
        ):
            tech_mitigations.setdefault(tgt_ext, set()).add(src_ext)
        elif (
            rel_type == "detects"
            and src_stix.startswith("x-mitre-detection-strategy--")
            and tgt_stix.startswith("attack-pattern--")
            and src_ext in detection_strategies
        ):
            tech_dets.setdefault(tgt_ext, set()).add(src_ext)

    techniques: dict[str, dict[str, Any]] = {}
    inactive_techniques: dict[str, dict[str, Any]] = {}

    for o in objects:
        if o.get("type") != "attack-pattern":
            continue
        ref = _extract_mitre_external_id(o)
        name = o.get("name")
        if not (ref and name):
            continue

        is_revoked = bool(o.get("revoked", False))
        is_deprecated = bool(o.get("x_mitre_deprecated", False))
        if is_revoked or is_deprecated:
            inactive_techniques[ref] = {
                "name": str(name),
                "status": "revoked" if is_revoked else "deprecated",
                "revoked_by": revoked_by_map.get(ref),
            }
            continue

        raw_phases = o.get("kill_chain_phases", [])
        tech_tactics = (
            [
                str(p.get("phase_name", ""))
                for p in raw_phases
                if isinstance(p, dict) and p.get("kill_chain_name") == "mitre-attack"
            ]
            if isinstance(raw_phases, list)
            else []
        )
        raw_platforms = o.get("x_mitre_platforms", [])
        platforms = (
            sorted({str(p).strip() for p in raw_platforms if str(p).strip()})
            if isinstance(raw_platforms, list)
            else []
        )
        dets = sorted(tech_dets.get(ref, set()))
        tech_dcs: set[str] = set()
        for det_id in dets:
            tech_dcs.update(det_to_dcs.get(det_id, set()))

        techniques[ref] = {
            "name": str(name),
            "tactics": sorted({t for t in tech_tactics if t}),
            "platforms": platforms,
            "groups": sorted(tech_groups.get(ref, set())),
            "mitigations": sorted(tech_mitigations.get(ref, set())),
            "detection_strategies": dets,
            "data_components": sorted(tech_dcs),
        }

    techniques["T0000"] = {
        "name": "Alert Forwarder / Unmapped Telemetry",
        "tactics": ["none"],
        "platforms": [],
        "groups": [],
        "mitigations": [],
        "detection_strategies": [],
        "data_components": [],
    }

    return {
        "version": resolved_version,
        "tactics": dict(sorted(tactics.items())),
        "legacy_tactics": legacy_tactics,
        "techniques": dict(sorted(techniques.items())),
        "inactive_techniques": dict(sorted(inactive_techniques.items())),
        "groups": dict(sorted(groups.items())),
        "mitigations": dict(sorted(mitigations.items())),
        "data_components": dict(sorted(data_components.items())),
        "detection_strategies": dict(sorted(detection_strategies.items())),
    }


def parse_attack_analytics_bundle(
    stix_data: dict[str, Any],
    version: str | None = None,
) -> dict[str, Any]:
    if not isinstance(stix_data, dict):
        raise ValueError("STIX bundle must be a JSON object")

    resolved_version = version if version is not None else _detect_bundle_version(stix_data)
    raw_objects = stix_data.get("objects", [])
    objects: list[dict[str, Any]] = (
        [o for o in raw_objects if isinstance(o, dict)] if isinstance(raw_objects, list) else []
    )

    stix_id_to_ext_id: dict[str, str] = {}
    for o in objects:
        stix_id = o.get("id")
        ext_id = _extract_mitre_external_id(o)
        if isinstance(stix_id, str) and ext_id:
            stix_id_to_ext_id[stix_id] = ext_id

    analytic_stix_to_strategy: dict[str, str] = {}
    for o in objects:
        if (
            o.get("type") == "x-mitre-detection-strategy"
            and not o.get("x_mitre_deprecated", False)
            and not o.get("revoked", False)
        ):
            det_id = _extract_mitre_external_id(o)
            an_refs = o.get("x_mitre_analytic_refs", [])
            if det_id and isinstance(an_refs, list):
                for an_stix in an_refs:
                    if isinstance(an_stix, str):
                        analytic_stix_to_strategy[an_stix] = det_id

    analytics: dict[str, dict[str, Any]] = {}
    for o in objects:
        if (
            o.get("type") == "x-mitre-analytic"
            and not o.get("x_mitre_deprecated", False)
            and not o.get("revoked", False)
        ):
            an_id = _extract_mitre_external_id(o)
            stix_id = o.get("id")
            name = o.get("name")
            if not (an_id and name):
                continue
            raw_platforms = o.get("x_mitre_platforms", [])
            platforms = (
                sorted({str(p).strip() for p in raw_platforms if str(p).strip()})
                if isinstance(raw_platforms, list)
                else []
            )
            log_sources: list[dict[str, str]] = []
            raw_ls = o.get("x_mitre_log_source_references", [])
            if isinstance(raw_ls, list):
                for ls in raw_ls:
                    if isinstance(ls, dict):
                        dc_stix = ls.get("x_mitre_data_component_ref")
                        dc_id = (
                            stix_id_to_ext_id.get(dc_stix, "") if isinstance(dc_stix, str) else ""
                        )
                        log_sources.append(
                            {
                                "data_component": dc_id,
                                "name": str(ls.get("name", "")),
                                "channel": str(ls.get("channel", "")),
                            }
                        )
            mutable_elements: list[dict[str, str]] = []
            raw_me = o.get("x_mitre_mutable_elements", [])
            if isinstance(raw_me, list):
                for me in raw_me:
                    if isinstance(me, dict):
                        mutable_elements.append(
                            {
                                "field": str(me.get("field", "")),
                                "description": str(me.get("description", "")),
                            }
                        )
            analytics[an_id] = {
                "name": str(name),
                "strategy_id": (
                    analytic_stix_to_strategy.get(stix_id, "") if isinstance(stix_id, str) else ""
                ),
                "platforms": platforms,
                "description": str(o.get("description", "")).strip(),
                "log_sources": log_sources,
                "mutable_elements": mutable_elements,
            }

    return {
        "version": resolved_version,
        "analytics": dict(sorted(analytics.items())),
    }


def resolve_upstream_stix_release(
    version: str | None = None,
    index_url: str | None = None,
    timeout: float = 5.0,
) -> tuple[str, str]:
    if version is not None:
        cleaned = version.strip().lstrip("vV")
        return cleaned, f"{DEFAULT_ATTACK_STIX_BASE_URL}/enterprise-attack-{cleaned}.json"

    target_index_url = index_url or DEFAULT_ATTACK_INDEX_URL
    if not target_index_url.startswith(("https://", "http://")):
        raise ValueError(
            f"Invalid index URL scheme: {target_index_url}. Must start with https:// or http://"
        )

    req = urllib.request.Request(target_index_url, headers={"User-Agent": "graft-updater"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        idx_data: Any = json.loads(resp.read().decode("utf-8"))

    if isinstance(idx_data, dict):
        collections = idx_data.get("collections", [])
        if isinstance(collections, list):
            for coll in collections:
                if not isinstance(coll, dict):
                    continue
                coll_name = str(coll.get("name", ""))
                if "Enterprise" in coll_name:
                    versions = coll.get("versions", [])
                    if isinstance(versions, list) and versions:
                        latest = versions[0]
                        if isinstance(latest, dict):
                            ver = str(latest.get("version", "")).strip()
                            url = str(latest.get("url", "")).strip()
                            if ver and url:
                                return ver, url

    return "19.2", DEFAULT_ATTACK_STIX_URL


def check_upstream_mitre_version(
    current_version: str | None = None,
    index_url: str | None = None,
    timeout: float = 2.0,
) -> dict[str, Any]:
    local_ver = current_version or get_default_mitre_validator().version
    try:
        latest_ver, latest_url = resolve_upstream_stix_release(
            version=None,
            index_url=index_url,
            timeout=timeout,
        )
        update_available = _parse_version_tuple(latest_ver) > _parse_version_tuple(local_ver)
        return {
            "current_version": local_ver,
            "latest_version": latest_ver,
            "update_available": update_available,
            "latest_url": latest_url,
            "offline": False,
        }
    except Exception:
        return {
            "current_version": local_ver,
            "latest_version": local_ver,
            "update_available": False,
            "latest_url": "",
            "offline": True,
        }


def update_mitre_taxonomy(
    source_url: str | None = None,
    target_path: Path | None = None,
    version: str | None = None,
    analytics_target_path: Path | None = None,
) -> dict[str, Any]:
    requested_version = version.strip().lstrip("vV") if version else None
    if source_url is not None:
        url = source_url
    elif requested_version is not None:
        _, url = resolve_upstream_stix_release(version=requested_version)
    else:
        try:
            requested_version, url = resolve_upstream_stix_release()
        except Exception:
            url = DEFAULT_ATTACK_STIX_URL

    if not (url.startswith("https://") or url.startswith("http://")):
        raise ValueError(
            f"Invalid STIX source URL scheme: {url}. Must start with https:// or http://"
        )

    req = urllib.request.Request(url, headers={"User-Agent": "graft-updater"})  # noqa: S310
    with urllib.request.urlopen(req) as resp:  # noqa: S310
        stix_data: dict[str, Any] = json.loads(resp.read().decode("utf-8"))

    payload = parse_attack_stix_bundle(stix_data, version=requested_version)
    analytics_payload = parse_attack_analytics_bundle(
        stix_data, version=str(payload.get("version", "19.2"))
    )

    if target_path is not None:
        dest = target_path
    else:
        resource = importlib.resources.files("graft.data").joinpath("mitre_attack.json")
        dest = Path(str(resource))

    if analytics_target_path is not None:
        an_dest = analytics_target_path
    elif target_path is not None:
        an_dest = target_path.parent / "mitre_analytics.json"
    else:
        an_resource = importlib.resources.files("graft.data").joinpath("mitre_analytics.json")
        an_dest = Path(str(an_resource))

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    an_dest.parent.mkdir(parents=True, exist_ok=True)
    an_dest.write_text(json.dumps(analytics_payload, indent=2) + "\n", encoding="utf-8")

    get_default_mitre_validator.cache_clear()
    payload["analytics_count"] = len(analytics_payload.get("analytics", {}))
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
        self._legacy_tactics: dict[str, dict[str, Any]] = data.get(
            "legacy_tactics",
            {
                "defense-evasion": {
                    "id": "TA0005",
                    "replaced_by": ["stealth", "defense-impairment"],
                }
            },
        )
        self._techniques: dict[str, dict[str, object]] = data.get("techniques", {})
        self._inactive_techniques: dict[str, dict[str, Any]] = data.get("inactive_techniques", {})

    @property
    def version(self) -> str:
        return self._version

    @property
    def tactics(self) -> dict[str, dict[str, str]]:
        return self._tactics

    @property
    def techniques(self) -> dict[str, dict[str, object]]:
        return self._techniques

    @property
    def inactive_techniques(self) -> dict[str, dict[str, Any]]:
        return self._inactive_techniques

    def resolve_tactic_ids(self, mitre_mappings: Mapping[str, Sequence[str]]) -> tuple[str, ...]:
        tactic_ids: set[str] = set()
        for tactic in mitre_mappings:
            norm = tactic.strip().lower()
            if norm in ("none", "ta0000"):
                continue
            if norm in self._tactics:
                tid = self._tactics[norm].get("id", "")
                if tid and tid.upper() != "TA0000":
                    tactic_ids.add(tid.upper())
            elif _TACTIC_ID_RE.match(norm):
                tactic_ids.add(norm.upper())
        return tuple(sorted(tactic_ids))

    def resolve_technique_ids(self, mitre_mappings: Mapping[str, Sequence[str]]) -> tuple[str, ...]:
        technique_ids: set[str] = set()
        for techniques in mitre_mappings.values():
            for tech in techniques:
                norm = tech.strip().upper()
                if norm and norm != "T0000" and _TECHNIQUE_ID_RE.match(norm):
                    technique_ids.add(norm)
        return tuple(sorted(technique_ids))

    def reconstruct_mitre_mapping(
        self,
        raw_tactics: Sequence[str],
        raw_techniques: Sequence[str],
    ) -> dict[str, tuple[str, ...]]:
        id_to_shortname: dict[str, str] = {
            info["id"].upper(): shortname
            for shortname, info in self._tactics.items()
            if shortname != "none" and "id" in info
        }
        declared_tactics: set[str] = set()
        for raw_t in raw_tactics:
            cleaned_t = raw_t.strip()
            if not cleaned_t:
                continue
            upper_t = cleaned_t.upper()
            lower_t = cleaned_t.lower()
            if upper_t == "TA0000" or lower_t == "none":
                continue
            if lower_t in self._legacy_tactics:
                for rep in self._legacy_tactics[lower_t].get("replaced_by", []):
                    declared_tactics.add(str(rep))
            elif upper_t in id_to_shortname:
                declared_tactics.add(id_to_shortname[upper_t])
            elif lower_t in self._tactics:
                declared_tactics.add(lower_t)

        grouped: dict[str, set[str]] = {}
        for raw_tech in raw_techniques:
            tech_id = raw_tech.strip().upper()
            if not tech_id or tech_id == "T0000":
                continue
            if tech_id not in self._techniques and tech_id in self._inactive_techniques:
                replacement = self._inactive_techniques[tech_id].get("revoked_by")
                if isinstance(replacement, str) and replacement in self._techniques:
                    tech_id = replacement

            tech_data = self._techniques.get(tech_id)
            if not isinstance(tech_data, dict):
                continue
            valid_tactics_raw = tech_data.get("tactics", [])
            if not isinstance(valid_tactics_raw, list):
                continue
            valid_tactics = [str(t) for t in valid_tactics_raw if str(t) and str(t) != "none"]
            if not valid_tactics:
                continue
            matching_tactics = [t for t in valid_tactics if t in declared_tactics]
            target_tactics = matching_tactics if matching_tactics else valid_tactics
            for tactic_name in target_tactics:
                grouped.setdefault(tactic_name, set()).add(tech_id)

        return {tactic: tuple(sorted(techs)) for tactic, techs in sorted(grouped.items())}

    def validate(self, mitre_mappings: Mapping[str, Sequence[str]]) -> list[MitreValidationError]:
        errors: list[MitreValidationError] = []

        for tactic, techniques in mitre_mappings.items():
            if tactic not in self._tactics:
                if tactic in self._legacy_tactics:
                    replaced_by = self._legacy_tactics[tactic].get("replaced_by", [])
                    hints: list[str] = []
                    for tech_id in techniques:
                        t_obj = self._techniques.get(tech_id)
                        if isinstance(t_obj, dict):
                            t_tactics = t_obj.get("tactics", [])
                            if isinstance(t_tactics, list) and t_tactics:
                                hints.append(f"{tech_id} -> {t_tactics}")
                    hint_suffix = f" Move {', '.join(hints)}." if hints else ""
                    errors.append(
                        MitreValidationError(
                            tactic=tactic,
                            technique=None,
                            message=(
                                f"MITRE tactic '{tactic}' was replaced in ATT&CK by "
                                f"{replaced_by}.{hint_suffix}"
                            ),
                        )
                    )
                else:
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
                    inactive = self._inactive_techniques.get(tech_id)
                    if isinstance(inactive, dict):
                        old_name = str(inactive.get("name", tech_id))
                        status = str(inactive.get("status", "deprecated"))
                        revoked_by = inactive.get("revoked_by")
                        if isinstance(revoked_by, str) and revoked_by:
                            rep_obj = self._techniques.get(revoked_by, {})
                            rep_name = (
                                str(rep_obj.get("name", "")) if isinstance(rep_obj, dict) else ""
                            )
                            rep_tactics = (
                                rep_obj.get("tactics", []) if isinstance(rep_obj, dict) else []
                            )
                            rep_detail = (
                                f" ({rep_name}, tactics: {rep_tactics})" if rep_name else ""
                            )
                            errors.append(
                                MitreValidationError(
                                    tactic=tactic,
                                    technique=tech_id,
                                    message=(
                                        f"MITRE technique '{tech_id}' ({old_name}) is revoked by "
                                        f"'{revoked_by}'{rep_detail}; update metadata.mitre to "
                                        f"'{revoked_by}'."
                                    ),
                                )
                            )
                        else:
                            errors.append(
                                MitreValidationError(
                                    tactic=tactic,
                                    technique=tech_id,
                                    message=(
                                        f"MITRE technique '{tech_id}' ({old_name}) is {status} in "
                                        f"ATT&CK v{self._version} with no direct replacement; "
                                        "remove or replace with an active technique."
                                    ),
                                )
                            )
                    else:
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


@functools.lru_cache(maxsize=1)
def get_default_mitre_validator() -> MitreValidator:
    return MitreValidator()
