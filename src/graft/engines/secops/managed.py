import logging

from graft.core.models.managed import (
    ManagedDeployment,
    ManagedExclusion,
    ManagedRuleSet,
    ManagedState,
)
from graft.core.ports.managed import ManagedEnginePort
from graft.engines.secops.client import SecOpsClient

logger = logging.getLogger("graft.secops.managed")


class SecOpsManagedAdapter(ManagedEnginePort):
    def __init__(self, client: SecOpsClient) -> None:
        self._client = client
        self._category_cache: dict[str, str] = {}

    def fetch_managed_state(self) -> ManagedState:
        logger.info("Fetching curated rulesets from Google SecOps API")
        raw_rulesets: list[dict[str, object]] = []
        page_token: str | None = None
        while True:
            params: dict[str, str] = {"pageSize": "100"}
            if page_token:
                params["pageToken"] = page_token
            response = self._client.request(
                "GET",
                "curatedRuleSetCategories/-/curatedRuleSets",
                params=params,
                api_version="v1alpha",
            )
            items = response.get("curatedRuleSets", [])
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        raw_rulesets.append(item)
            next_token = response.get("nextPageToken")
            page_token = str(next_token) if next_token else None
            if not page_token:
                break

        # Attempt to fetch all deployments in bulk across all rulesets
        deployments_by_ruleset: dict[str, list[ManagedDeployment]] = {}
        dep_page_token: str | None = None
        while True:
            dep_params: dict[str, str] = {"pageSize": "200"}
            if dep_page_token:
                dep_params["pageToken"] = dep_page_token
            dep_resp = self._client.request(
                "GET",
                "curatedRuleSetCategories/-/curatedRuleSets/-/curatedRuleSetDeployments",
                params=dep_params,
                api_version="v1alpha",
            )
            raw_deps = dep_resp.get("curatedRuleSetDeployments", [])
            if isinstance(raw_deps, list) and raw_deps:
                for dep in raw_deps:
                    if not isinstance(dep, dict):
                        continue
                    dep_name = str(dep.get("name", ""))
                    parts = dep_name.split("/")
                    if "curatedRuleSets" in parts and "curatedRuleSetDeployments" in parts:
                        rs_id = parts[parts.index("curatedRuleSets") + 1]
                    else:
                        continue
                    precision_raw = str(dep.get("precision", "")).upper()
                    if precision_raw:
                        dep_type = precision_raw
                    else:
                        dep_type = "PRECISE" if dep_name.lower().endswith("/precise") else "BROAD"
                    deployments_by_ruleset.setdefault(rs_id, []).append(
                        ManagedDeployment(
                            type=dep_type,
                            enabled=bool(dep.get("enabled", False)),
                            alerting=bool(dep.get("alerting", False)),
                        )
                    )
            next_dep_token = dep_resp.get("nextPageToken")
            dep_page_token = str(next_dep_token) if next_dep_token else None
            if not dep_page_token:
                break

        # Resolve category UUID to category display name
        category_names: dict[str, str] = {}
        try:
            cat_resp = self._client.request(
                "GET",
                "curatedRuleSetCategories",
                api_version="v1alpha",
            )
            raw_cats = cat_resp.get("curatedRuleSetCategories", [])
            if isinstance(raw_cats, list):
                for cat in raw_cats:
                    if isinstance(cat, dict):
                        cat_res = str(cat.get("name", ""))
                        cat_disp = str(cat.get("displayName", ""))
                        cat_uuid = cat_res.split("/")[-1] if "/" in cat_res else cat_res
                        if cat_uuid and cat_disp:
                            category_names[cat_uuid] = cat_disp
        except Exception as exc:
            logger.debug("Failed resolving category names: %s", exc)

        rulesets: list[ManagedRuleSet] = []
        for raw in raw_rulesets:
            name_resource = str(raw.get("name", ""))
            display_name = str(raw.get("displayName", ""))

            parts = name_resource.split("/")
            category = "default"
            ruleset_id = name_resource
            if "curatedRuleSetCategories" in parts and "curatedRuleSets" in parts:
                cat_idx = parts.index("curatedRuleSetCategories") + 1
                rs_idx = parts.index("curatedRuleSets") + 1
                if cat_idx < len(parts):
                    category = parts[cat_idx]
                if rs_idx < len(parts):
                    ruleset_id = parts[rs_idx]
            elif "/" in name_resource:
                ruleset_id = parts[-1]

            category_uuid = category
            category_name = category_names.get(category_uuid, category_uuid)
            self._category_cache[ruleset_id] = category_uuid

            # Check if deployments were fetched in bulk
            deployments = list(deployments_by_ruleset.get(ruleset_id, []))
            if not deployments:
                # Fallback: per-ruleset fetch (e.g. In mock environments)
                deployments_path = (
                    f"curatedRuleSetCategories/{category}/curatedRuleSets/"
                    f"{ruleset_id}/curatedRuleSetDeployments"
                )
                deployments_resp = self._client.request(
                    "GET", deployments_path, api_version="v1alpha"
                )
                raw_deployments = deployments_resp.get("curatedRuleSetDeployments", [])
                if isinstance(raw_deployments, list):
                    for dep in raw_deployments:
                        if not isinstance(dep, dict):
                            continue
                        dep_name = str(dep.get("name", ""))
                        precision_raw = str(dep.get("precision", "")).upper()
                        if precision_raw:
                            dep_type = precision_raw
                        else:
                            dep_type = (
                                "PRECISE" if dep_name.lower().endswith("/precise") else "BROAD"
                            )
                        deployments.append(
                            ManagedDeployment(
                                type=dep_type,
                                enabled=bool(dep.get("enabled", False)),
                                alerting=bool(dep.get("alerting", False)),
                            )
                        )

            if not deployments:
                deployments = [
                    ManagedDeployment(type="PRECISE", enabled=False, alerting=False),
                    ManagedDeployment(type="BROAD", enabled=False, alerting=False),
                ]

            deployments.sort(key=lambda d: 0 if d.type == "PRECISE" else 1)

            rulesets.append(
                ManagedRuleSet(
                    id=ruleset_id,
                    name=display_name or ruleset_id,
                    category=category_name,
                    deployments=tuple(deployments),
                    category_id=category_uuid,
                )
            )

        # Fetch exclusions (findingsRefinements)
        logger.info("Fetching findings refinements from Google SecOps API")
        raw_exclusions: list[dict[str, object]] = []
        ex_page_token: str | None = None
        while True:
            ex_params: dict[str, str] = {}
            if ex_page_token:
                ex_params["pageToken"] = ex_page_token
            excl_resp = self._client.request(
                "GET",
                "findingsRefinements",
                params=ex_params if ex_params else None,
                api_version="v1alpha",
            )
            items = excl_resp.get("findingsRefinements", [])
            if isinstance(items, list):
                for it in items:
                    if isinstance(it, dict):
                        raw_exclusions.append(it)
            next_ex_token = excl_resp.get("nextPageToken")
            ex_page_token = str(next_ex_token) if next_ex_token else None
            if not ex_page_token:
                break

        exclusions: list[ManagedExclusion] = []
        for raw_ex in raw_exclusions:
            name_res = str(raw_ex.get("name", ""))
            excl_id = name_res.split("/")[-1] if "/" in name_res else name_res
            desc = str(raw_ex.get("displayName", ""))
            query = str(raw_ex.get("query", ""))

            applied_rules = raw_ex.get("appliedDetectionRules")
            rule_id: str | None = None
            if isinstance(applied_rules, list) and applied_rules:
                rule_id = str(applied_rules[0])

            applied_curated = raw_ex.get("appliedCuratedRuleSets")
            ruleset_id_ex: str | None = None
            if isinstance(applied_curated, list) and applied_curated:
                first_curated = str(applied_curated[0])
                ruleset_id_ex = (
                    first_curated.split("/")[-1] if "/" in first_curated else first_curated
                )

            exclusions.append(
                ManagedExclusion(
                    id=excl_id,
                    rule_id=rule_id,
                    ruleset_id=ruleset_id_ex,
                    expression=query,
                    description=desc,
                )
            )

        return ManagedState(
            rulesets=tuple(rulesets),
            exclusions=tuple(exclusions),
        )

    def set_ruleset_deployment(
        self,
        ruleset_id: str,
        deployment_type: str,
        enabled: bool,
        alerting: bool,
        category: str | None = None,
    ) -> None:
        cat = category or self._category_cache.get(ruleset_id, "default")
        path = (
            f"curatedRuleSetCategories/{cat}/curatedRuleSets/{ruleset_id}/curatedRuleSetDeployments/"
            f"{deployment_type.lower()}"
        )
        logger.info(
            "Setting ruleset deployment: %s (%s) [enabled=%s, alerting=%s]",
            ruleset_id,
            deployment_type,
            enabled,
            alerting,
        )
        self._client.request(
            "PATCH",
            path,
            body={"enabled": enabled, "alerting": alerting},
            params={"update_mask": "enabled,alerting"},
            api_version="v1alpha",
        )

    def create_exclusion(self, exclusion: ManagedExclusion) -> str:
        body: dict[str, object] = {
            "displayName": exclusion.description,
            "query": exclusion.expression,
            "type": "DETECTION_EXCLUSION",
        }
        if exclusion.ruleset_id:
            cat = self._category_cache.get(exclusion.ruleset_id, "default")
            curated_res = (
                f"projects/{self._client._config.project}/locations/{self._client._config.location}/"
                f"instances/{self._client._config.instance_id}/curatedRuleSetCategories/{cat}/"
                f"curatedRuleSets/{exclusion.ruleset_id}"
            )
            body["appliedCuratedRuleSets"] = [curated_res]
        if exclusion.rule_id:
            body["appliedDetectionRules"] = [exclusion.rule_id]

        logger.info("Creating findings refinement exclusion '%s'", exclusion.id)
        self._client.request(
            "POST",
            "findingsRefinements",
            body=body,
            params={"findings_refinement_id": exclusion.id},
            api_version="v1alpha",
        )
        return exclusion.id

    def update_exclusion(self, exclusion: ManagedExclusion) -> None:
        body: dict[str, object] = {
            "displayName": exclusion.description,
            "query": exclusion.expression,
        }
        if exclusion.ruleset_id:
            cat = self._category_cache.get(exclusion.ruleset_id, "default")
            curated_res = (
                f"projects/{self._client._config.project}/locations/{self._client._config.location}/"
                f"instances/{self._client._config.instance_id}/curatedRuleSetCategories/{cat}/"
                f"curatedRuleSets/{exclusion.ruleset_id}"
            )
            body["appliedCuratedRuleSets"] = [curated_res]
        if exclusion.rule_id:
            body["appliedDetectionRules"] = [exclusion.rule_id]

        logger.info("Updating findings refinement exclusion '%s'", exclusion.id)
        self._client.request(
            "PATCH",
            f"findingsRefinements/{exclusion.id}",
            body=body,
            params={
                "update_mask": "displayName,query,appliedCuratedRuleSets,appliedDetectionRules"
            },
            api_version="v1alpha",
        )

    def delete_exclusion(self, exclusion_id: str) -> None:
        logger.info("Deleting findings refinement exclusion '%s'", exclusion_id)
        self._client.request(
            "DELETE",
            f"findingsRefinements/{exclusion_id}",
            api_version="v1alpha",
        )

    def apply_managed_state(self, target_state: ManagedState) -> None:
        # Import lazily or at top level from core
        from graft.core.reconciler import GitOpsReconciler

        reconciler = GitOpsReconciler()
        reconciler.apply(desired=target_state, port=self)
