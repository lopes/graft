from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from graft.core.models.rule import (
    BaseDeploymentConfig,
    RuleEnvelope,
    RuleMetadata,
    Runbook,
)
from graft.core.ports.deployer import RuleDeployerPort
from graft.engines.gti.client import GTIApiError, GTIClient, quote_path_segment
from graft.engines.gti.compiler import (
    deconstruct_yara_rule,
    resolve_gti_subtype,
    synthesize_yara_rule,
)

logger = logging.getLogger("graft.gti.deployer")

_VALID_DEPLOYMENT_TYPES = frozenset({"livehunt", "retrohunt"})
_VALID_CORPORA = frozenset({"main", "goodware"})


def _safe_int(value: object, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


def resolve_gti_deployment_type(rule: RuleEnvelope) -> str:
    raw = rule.deployment.get("type")
    if isinstance(raw, str) and raw in _VALID_DEPLOYMENT_TYPES:
        return raw
    raise ValueError(
        f"Rule '{rule.metadata.name}' has invalid or missing deployment.type '{raw}'; "
        "GTI rules require deployment.type to be 'livehunt' or 'retrohunt'"
    )


def resolve_gti_corpus(rule: RuleEnvelope) -> str:
    raw = rule.deployment.get("corpus")
    if isinstance(raw, str) and raw in _VALID_CORPORA:
        return raw
    raise ValueError(
        f"Rule '{rule.metadata.name}' has invalid or missing deployment.corpus '{raw}'; "
        "Retrohunt rules require deployment.corpus to be 'main' or 'goodware'"
    )


def _iso_to_unix_epoch(iso_str: str) -> int:
    normalized = iso_str.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return int(dt.timestamp())


def _unix_epoch_to_iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_gti_deployment(
    rule: RuleEnvelope,
    default_emails: tuple[str, ...] = (),
) -> dict[str, object]:
    dep_type = resolve_gti_deployment_type(rule)
    enabled = bool(rule.deployment.get("enabled", True))
    raw_emails = rule.deployment.get("notification_emails")
    if isinstance(raw_emails, (list, tuple)):
        emails = [str(e).strip() for e in raw_emails if str(e).strip()]
    else:
        emails = [str(e).strip() for e in default_emails if str(e).strip()]

    if dep_type == "retrohunt":
        corpus = resolve_gti_corpus(rule)
        norm: dict[str, object] = {
            "type": "retrohunt",
            "enabled": enabled,
            "corpus": corpus,
        }
        start_val = rule.deployment.get("start_time")
        end_val = rule.deployment.get("end_time")
        if isinstance(start_val, str) and start_val.strip():
            norm["start_time"] = _unix_epoch_to_iso(_iso_to_unix_epoch(start_val))
        if isinstance(end_val, str) and end_val.strip():
            norm["end_time"] = _unix_epoch_to_iso(_iso_to_unix_epoch(end_val))
        if emails:
            norm["notification_emails"] = emails
        return norm

    raw_limit = rule.deployment.get("daily_limit", 100)
    daily_limit = _safe_int(raw_limit, 100)
    norm_lh: dict[str, object] = {
        "type": "livehunt",
        "subtype": resolve_gti_subtype(rule),
        "enabled": enabled,
        "daily_limit": daily_limit,
    }
    if emails:
        norm_lh["notification_emails"] = emails
    return norm_lh


class GTIDeployerAdapter(RuleDeployerPort):
    def __init__(self, client: GTIClient) -> None:
        self._client = client
        self._remote_index: dict[str, tuple[str, str, str]] = {}

    def _record_remote_resource(
        self,
        rule: RuleEnvelope,
        gti_resource_id: str,
        owner_id: str,
        dep_type: str = "livehunt",
        current_user_id: str = "",
    ) -> None:
        entry = (gti_resource_id, owner_id, dep_type)
        if gti_resource_id:
            self._remote_index[gti_resource_id] = entry
        for key in (rule.metadata.id, rule.metadata.name):
            if not key:
                continue
            existing = self._remote_index.get(key)
            if (
                existing is not None
                and current_user_id
                and existing[1] == current_user_id
                and owner_id != current_user_id
            ):
                continue
            self._remote_index[key] = entry

    def _resolve_owned_resource(
        self,
        identifier: str,
        fallback_name: str = "",
        default_type: str = "livehunt",
    ) -> tuple[str, str]:
        current_user_id = self._client.get_current_user_id()
        entry = self._remote_index.get(identifier) or (
            self._remote_index.get(fallback_name) if fallback_name else None
        )
        if entry is None:
            self.list_rules()
            entry = self._remote_index.get(identifier) or (
                self._remote_index.get(fallback_name) if fallback_name else None
            )
        if entry is None:
            return identifier, default_type

        gti_id, owner_id, dep_type = entry
        endpoint_base = (
            "/intelligence/retrohunt_jobs"
            if dep_type == "retrohunt"
            else "/intelligence/hunting_rulesets"
        )
        if owner_id and owner_id != current_user_id:
            raise GTIApiError(
                message=(
                    f"Refusing to modify or delete GTI {dep_type} '{gti_id}' ({identifier}): "
                    f"resource is owned by another user ('{owner_id}') in the shared GTI org"
                ),
                status_code=403,
                error_code="OwnershipGuardError",
                method="MUTATE",
                path=f"{endpoint_base}/{gti_id}",
            )
        return gti_id, dep_type

    def should_deploy_rule(self, rule: RuleEnvelope) -> bool:
        if resolve_gti_deployment_type(rule) == "retrohunt":
            return bool(rule.deployment.get("enabled", False))
        return True

    def are_deployments_equal(
        self,
        desired: RuleEnvelope,
        remote: RuleEnvelope,
    ) -> bool:
        default_emails = self._client.config.notification_emails
        return normalize_gti_deployment(desired, default_emails) == normalize_gti_deployment(
            remote, default_emails
        )

    def _extract_owner_id(self, item: dict[str, Any], default_owner: str) -> str:
        rels = item.get("relationships", {})
        if isinstance(rels, dict):
            owner_rel = rels.get("owner", {})
            if isinstance(owner_rel, dict):
                owner_data = owner_rel.get("data", {})
                if isinstance(owner_data, dict) and owner_data.get("id"):
                    return str(owner_data["id"])
        return default_owner

    def _list_livehunt_rulesets(
        self,
        current_user_id: str,
        ruleset_filter: str,
    ) -> list[RuleEnvelope]:
        if ruleset_filter == "owner:self":
            safe_uid = quote_path_segment(current_user_id)
            base_path = f"/users/{safe_uid}/hunting_rulesets"
            base_params: dict[str, str] = {"limit": "40", "relationships": "owner"}
        elif ruleset_filter == "all":
            base_path = "/intelligence/hunting_rulesets"
            base_params = {"limit": "40", "relationships": "owner"}
        else:
            base_path = "/intelligence/hunting_rulesets"
            base_params = {
                "limit": "40",
                "filter": ruleset_filter,
                "relationships": "owner",
            }

        rules: list[RuleEnvelope] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        while True:
            params = dict(base_params)
            if cursor:
                params["cursor"] = cursor
            payload = self._client.get(base_path, params=params)
            items = payload.get("data", [])
            if not isinstance(items, list):
                break

            for item in items:
                if not isinstance(item, dict):
                    continue
                gti_id = str(item.get("id", ""))
                attrs = item.get("attributes", {})
                if not isinstance(attrs, dict):
                    continue

                default_owner = current_user_id if ruleset_filter == "owner:self" else ""
                owner_id = self._extract_owner_id(item, default_owner)

                name = str(attrs.get("name") or gti_id)
                raw_yara = str(attrs.get("rules") or "")
                enabled = bool(attrs.get("enabled", False))
                subtype = str(attrs.get("match_object_type") or "file")
                daily_limit = _safe_int(attrs.get("limit"), 100)
                raw_notif = attrs.get("notification_emails")
                notif_emails = [
                    str(e)
                    for e in (raw_notif if isinstance(raw_notif, list) else [])
                    if isinstance(e, str) and e.strip()
                ]
                raw_tags_attr = attrs.get("tags")
                raw_tags = tuple(
                    str(t).strip()
                    for t in (raw_tags_attr if isinstance(raw_tags_attr, list) else [])
                    if isinstance(t, str) and str(t).strip()
                )

                dep_dict: dict[str, object] = {
                    "type": "livehunt",
                    "subtype": subtype,
                    "enabled": enabled,
                    "daily_limit": daily_limit,
                }
                if notif_emails:
                    dep_dict["notification_emails"] = notif_emails

                raw_envelope = RuleEnvelope(
                    metadata=RuleMetadata(
                        id="",
                        name=name,
                        description="",
                        tags=raw_tags,
                    ),
                    logic=raw_yara,
                    deployment=BaseDeploymentConfig.from_dict(dep_dict),
                    runbook=Runbook(),
                )
                deconstructed = deconstruct_yara_rule(raw_envelope)
                self._record_remote_resource(
                    deconstructed,
                    gti_id,
                    owner_id,
                    "livehunt",
                    current_user_id=current_user_id,
                )
                if ruleset_filter == "owner:self" and owner_id and owner_id != current_user_id:
                    logger.debug(
                        "Skipping group-editable Livehunt ruleset '%s' owned by '%s' "
                        "(owner:self scope)",
                        gti_id,
                        owner_id,
                    )
                    continue
                rules.append(deconstructed)

            meta = payload.get("meta", {})
            next_cursor = meta.get("cursor") if isinstance(meta, dict) else None
            next_cursor_str = str(next_cursor).strip() if next_cursor else ""
            if not next_cursor_str or not items or next_cursor_str in seen_cursors:
                break
            seen_cursors.add(next_cursor_str)
            cursor = next_cursor_str

        return rules

    def _list_retrohunt_jobs(
        self,
        current_user_id: str,
        ruleset_filter: str,
    ) -> list[RuleEnvelope]:
        if ruleset_filter == "owner:self":
            safe_uid = quote_path_segment(current_user_id)
            base_path = f"/users/{safe_uid}/retrohunt_jobs"
            base_params: dict[str, str] = {"limit": "40", "relationships": "owner"}
        else:
            base_path = "/intelligence/retrohunt_jobs"
            base_params = {"limit": "40", "relationships": "owner"}

        rules: list[RuleEnvelope] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        while True:
            params = dict(base_params)
            if cursor:
                params["cursor"] = cursor
            try:
                payload = self._client.get(base_path, params=params)
            except GTIApiError as exc:
                if exc.status_code in (403, 404, 501):
                    logger.debug(
                        "Retrohunt listing unavailable on %s (HTTP %d); "
                        "skipping Retrohunt inventory",
                        base_path,
                        exc.status_code,
                    )
                    break
                logger.warning("Failed listing GTI Retrohunt jobs on %s: %s", base_path, exc)
                raise
            items = payload.get("data", [])
            if not isinstance(items, list):
                break

            for item in items:
                if not isinstance(item, dict):
                    continue
                gti_id = str(item.get("id", ""))
                attrs = item.get("attributes", {})
                if not isinstance(attrs, dict):
                    continue

                default_owner = current_user_id if ruleset_filter == "owner:self" else ""
                owner_id = self._extract_owner_id(item, default_owner)

                raw_yara = str(attrs.get("rules") or "")
                if not raw_yara.strip():
                    if gti_id:
                        self._remote_index[gti_id] = (gti_id, owner_id, "retrohunt")
                    continue
                status = str(attrs.get("status") or "finished")
                enabled = status != "aborted"
                corpus = str(attrs.get("corpus") or "main")

                dep_dict: dict[str, object] = {
                    "type": "retrohunt",
                    "enabled": enabled,
                    "corpus": corpus,
                }
                tr = attrs.get("time_range")
                if isinstance(tr, dict):
                    start_raw = tr.get("start")
                    end_raw = tr.get("end")
                    if not isinstance(start_raw, bool) and isinstance(start_raw, (int, float)):
                        dep_dict["start_time"] = _unix_epoch_to_iso(int(start_raw))
                    if not isinstance(end_raw, bool) and isinstance(end_raw, (int, float)):
                        dep_dict["end_time"] = _unix_epoch_to_iso(int(end_raw))

                notif_email = attrs.get("notification_email")
                if isinstance(notif_email, str) and notif_email.strip():
                    dep_dict["notification_emails"] = [
                        e.strip() for e in notif_email.split(",") if e.strip()
                    ]

                raw_envelope = RuleEnvelope(
                    metadata=RuleMetadata(
                        id="",
                        name="",
                        description="",
                        tags=(),
                    ),
                    logic=raw_yara,
                    deployment=BaseDeploymentConfig.from_dict(dep_dict),
                    runbook=Runbook(),
                )
                deconstructed = deconstruct_yara_rule(raw_envelope)
                self._record_remote_resource(
                    deconstructed,
                    gti_id,
                    owner_id,
                    "retrohunt",
                    current_user_id=current_user_id,
                )
                if ruleset_filter == "owner:self" and owner_id and owner_id != current_user_id:
                    logger.debug(
                        "Skipping Retrohunt job '%s' owned by '%s' (owner:self scope)",
                        gti_id,
                        owner_id,
                    )
                    continue
                if ruleset_filter.startswith("tag:"):
                    required_tag = ruleset_filter[len("tag:") :].strip()
                    if required_tag and required_tag not in deconstructed.metadata.tags:
                        continue
                rules.append(deconstructed)

            meta = payload.get("meta", {})
            next_cursor = meta.get("cursor") if isinstance(meta, dict) else None
            next_cursor_str = str(next_cursor).strip() if next_cursor else ""
            if not next_cursor_str or not items or next_cursor_str in seen_cursors:
                break
            seen_cursors.add(next_cursor_str)
            cursor = next_cursor_str

        return rules

    def list_rules(self) -> tuple[RuleEnvelope, ...]:
        ruleset_filter = self._client.config.ruleset_filter
        current_user_id = self._client.get_current_user_id()

        livehunt_rules = self._list_livehunt_rulesets(current_user_id, ruleset_filter)
        retrohunt_rules = self._list_retrohunt_jobs(current_user_id, ruleset_filter)
        return tuple([*livehunt_rules, *retrohunt_rules])

    def _resolve_notification_emails(self, rule: RuleEnvelope) -> list[str]:
        raw_emails = rule.deployment.get("notification_emails")
        if isinstance(raw_emails, (list, tuple)):
            return [str(e).strip() for e in raw_emails if str(e).strip()]
        return list(self._client.config.notification_emails)

    def _build_livehunt_attributes(self, rule: RuleEnvelope) -> dict[str, Any]:
        yara_text, _ = synthesize_yara_rule(rule)
        subtype = resolve_gti_subtype(rule)
        raw_limit = rule.deployment.get("daily_limit", 100)
        daily_limit = _safe_int(raw_limit, 100)
        emails = self._resolve_notification_emails(rule)
        tags = list(dict.fromkeys(t for t in rule.metadata.tags if t))

        return {
            "name": rule.metadata.name,
            "rules": yara_text,
            "enabled": bool(rule.deployment.get("enabled", True)),
            "match_object_type": subtype,
            "limit": daily_limit,
            "notification_emails": emails,
            "tags": tags,
        }

    def _build_retrohunt_attributes(self, rule: RuleEnvelope) -> dict[str, Any]:
        yara_text, _ = synthesize_yara_rule(rule)
        corpus = resolve_gti_corpus(rule)
        attrs: dict[str, Any] = {
            "rules": yara_text,
            "corpus": corpus,
        }
        start_val = rule.deployment.get("start_time")
        end_val = rule.deployment.get("end_time")
        time_range: dict[str, int] = {}
        if isinstance(start_val, str) and start_val.strip():
            time_range["start"] = _iso_to_unix_epoch(start_val)
        if isinstance(end_val, str) and end_val.strip():
            time_range["end"] = _iso_to_unix_epoch(end_val)
        if time_range:
            attrs["time_range"] = time_range

        emails = self._resolve_notification_emails(rule)
        if emails:
            attrs["notification_email"] = ", ".join(emails)
        return attrs

    def create_rule(self, rule: RuleEnvelope) -> str:
        dep_type = resolve_gti_deployment_type(rule)
        current_user_id = self._client.get_current_user_id()

        if dep_type == "retrohunt":
            if not bool(rule.deployment.get("enabled", False)):
                logger.debug(
                    "Skipping remote submission of disabled GTI Retrohunt job '%s'",
                    rule.metadata.name,
                )
                return rule.metadata.id
            logger.debug(
                "Submitting GTI Retrohunt job '%s' (%s)",
                rule.metadata.name,
                rule.metadata.id,
            )
            payload = {
                "data": {
                    "type": "retrohunt_job",
                    "attributes": self._build_retrohunt_attributes(rule),
                }
            }
            resp = self._client.post("/intelligence/retrohunt_jobs", payload)
            data = resp.get("data", {})
            gti_id = (
                str(data.get("id", rule.metadata.id))
                if isinstance(data, dict)
                else rule.metadata.id
            )
            self._record_remote_resource(rule, gti_id, current_user_id, "retrohunt")
            return gti_id

        logger.debug(
            "Creating GTI Livehunt ruleset '%s' (%s)",
            rule.metadata.name,
            rule.metadata.id,
        )
        payload = {
            "data": {
                "type": "hunting_ruleset",
                "attributes": self._build_livehunt_attributes(rule),
            }
        }
        resp = self._client.post("/intelligence/hunting_rulesets", payload)
        data = resp.get("data", {})
        gti_id = (
            str(data.get("id", rule.metadata.id)) if isinstance(data, dict) else rule.metadata.id
        )
        self._record_remote_resource(rule, gti_id, current_user_id, "livehunt")
        return gti_id

    def update_rule(self, rule: RuleEnvelope) -> None:
        dep_type = resolve_gti_deployment_type(rule)
        gti_id, existing_type = self._resolve_owned_resource(
            rule.metadata.id,
            fallback_name=rule.metadata.name,
            default_type=dep_type,
        )

        if existing_type == "retrohunt" or dep_type == "retrohunt":
            logger.debug(
                "Updating GTI Retrohunt rule '%s' (%s) without deleting existing job results",
                rule.metadata.name,
                rule.metadata.id,
            )
            if existing_type == "livehunt":
                safe_id = quote_path_segment(gti_id)
                self._client.delete(f"/intelligence/hunting_rulesets/{safe_id}")
            if dep_type == "livehunt" or (
                dep_type == "retrohunt" and bool(rule.deployment.get("enabled", False))
            ):
                self.create_rule(rule)
            return

        logger.debug(
            "Updating GTI Livehunt ruleset '%s' (%s)",
            rule.metadata.name,
            rule.metadata.id,
        )
        safe_id = quote_path_segment(gti_id)
        payload = {
            "data": {
                "type": "hunting_ruleset",
                "id": gti_id,
                "attributes": self._build_livehunt_attributes(rule),
            }
        }
        self._client.patch(f"/intelligence/hunting_rulesets/{safe_id}", payload)

    def delete_rule(self, rule_id: str) -> None:
        gti_id, dep_type = self._resolve_owned_resource(rule_id)
        safe_id = quote_path_segment(gti_id)
        if dep_type == "retrohunt":
            logger.debug("Deleting GTI Retrohunt job '%s'", rule_id)
            self._client.delete(f"/intelligence/retrohunt_jobs/{safe_id}")
            return
        logger.debug("Deleting GTI Livehunt ruleset '%s'", rule_id)
        self._client.delete(f"/intelligence/hunting_rulesets/{safe_id}")

    def set_rule_state(self, rule_id: str, enabled: bool, alerting: bool) -> None:
        gti_id, dep_type = self._resolve_owned_resource(rule_id)
        if dep_type == "retrohunt":
            logger.debug(
                "Preserving existing GTI Retrohunt job '%s' state "
                "(running tasks and results are not aborted)",
                rule_id,
            )
            return
        logger.debug(
            "Setting GTI Livehunt ruleset '%s' state (enabled=%s, alerting=%s)",
            rule_id,
            enabled,
            alerting,
        )
        attrs: dict[str, Any] = {"enabled": enabled}
        if not alerting:
            attrs["notification_emails"] = []
        elif self._client.config.notification_emails:
            attrs["notification_emails"] = list(self._client.config.notification_emails)
        safe_id = quote_path_segment(gti_id)
        payload = {
            "data": {
                "type": "hunting_ruleset",
                "id": gti_id,
                "attributes": attrs,
            }
        }
        self._client.patch(f"/intelligence/hunting_rulesets/{safe_id}", payload)
