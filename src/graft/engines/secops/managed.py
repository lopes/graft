import logging
from typing import cast

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
        self._category_name_to_id: dict[str, str] = {}
        self._category_id_to_name: dict[str, str] = {}

    def _populate_category_caches(self) -> None:
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
                        if cat_uuid:
                            if cat_disp:
                                self._category_name_to_id[cat_disp] = cat_uuid
                                self._category_name_to_id[cat_disp.lower()] = cat_uuid
                                self._category_id_to_name[cat_uuid] = cat_disp
                            self._category_name_to_id[cat_uuid] = cat_uuid
        except Exception as exc:
            logger.debug("Failed resolving category names: %s", exc)

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

        self._populate_category_caches()

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
            category_name = self._category_id_to_name.get(category_uuid, category_uuid)
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

        # Attempt bulk fetch of refinement deployments
        deployments_by_refinement: dict[str, dict[str, object]] = {}
        dep_ref_page_token: str | None = None
        while True:
            dep_ref_params: dict[str, str] = {"pageSize": "200"}
            if dep_ref_page_token:
                dep_ref_params["pageToken"] = dep_ref_page_token
            try:
                dep_ref_resp = self._client.request(
                    "GET",
                    ":listAllFindingsRefinementDeployments",
                    params=dep_ref_params,
                    api_version="v1alpha",
                )
            except Exception as exc:
                logger.debug("Bulk list findings refinement deployments not available: %s", exc)
                break

            raw_ref_deps = dep_ref_resp.get("allFindingsRefinementDeployments") or dep_ref_resp.get(
                "findingsRefinementDeployments", []
            )
            if isinstance(raw_ref_deps, list) and raw_ref_deps:
                for d in raw_ref_deps:
                    if isinstance(d, dict):
                        d_name = str(d.get("name", ""))
                        parts = d_name.split("/")
                        if "findingsRefinements" in parts:
                            f_idx = parts.index("findingsRefinements") + 1
                            if f_idx < len(parts):
                                deployments_by_refinement[parts[f_idx]] = d
            next_ref_dep_token = dep_ref_resp.get("nextPageToken")
            dep_ref_page_token = str(next_ref_dep_token) if next_ref_dep_token else None
            if not dep_ref_page_token:
                break

        exclusions: list[ManagedExclusion] = []
        for raw_ex in raw_exclusions:
            name_res = str(raw_ex.get("name", ""))
            excl_id = name_res.split("/")[-1] if "/" in name_res else name_res
            desc = str(raw_ex.get("displayName", ""))
            query = str(raw_ex.get("query", ""))

            dep_data = deployments_by_refinement.get(excl_id)
            if dep_data is None:
                try:
                    dep_resp = self._client.request(
                        "GET", f"findingsRefinements/{excl_id}/deployment", api_version="v1alpha"
                    )
                    if isinstance(dep_resp, dict):
                        dep_data = dep_resp
                except Exception as exc:
                    logger.debug("Failed fetching deployment for refinement '%s': %s", excl_id, exc)

            if dep_data and dep_data.get("archived") is True:
                continue

            rule_id: str | None = None
            ruleset_id_ex: str | None = None

            if dep_data and isinstance(dep_data.get("detectionExclusionApplication"), dict):
                app = cast(dict[str, object], dep_data["detectionExclusionApplication"])
                curated_sets = app.get("curatedRuleSets")
                if isinstance(curated_sets, list) and curated_sets:
                    first_curated = str(curated_sets[0])
                    ruleset_id_ex = (
                        first_curated.split("/")[-1] if "/" in first_curated else first_curated
                    )
                rules_list = app.get("rules")
                if isinstance(rules_list, list) and rules_list:
                    first_rule = str(rules_list[0])
                    rule_id = first_rule.split("/")[-1] if "/" in first_rule else first_rule

            if not rule_id:
                applied_rules = raw_ex.get("appliedDetectionRules")
                if isinstance(applied_rules, list) and applied_rules:
                    rule_id = str(applied_rules[0])
            if not ruleset_id_ex:
                applied_curated = raw_ex.get("appliedCuratedRuleSets")
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
        cat: str | None = None
        if ruleset_id in self._category_cache:
            cat = self._category_cache[ruleset_id]
        elif category and category in self._category_name_to_id:
            cat = self._category_name_to_id[category]
        elif category and category.lower() in self._category_name_to_id:
            cat = self._category_name_to_id[category.lower()]
        elif category and " " not in category and category != "default":
            cat = category
        else:
            if category and " " in category:
                self._populate_category_caches()
                if category in self._category_name_to_id:
                    cat = self._category_name_to_id[category]
                elif category.lower() in self._category_name_to_id:
                    cat = self._category_name_to_id[category.lower()]

            if not cat or " " in cat:
                cat = "-"

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
        logger.info("Creating findings refinement '%s' (%s)", exclusion.id, exclusion.description)
        resp = self._client.request(
            "POST",
            "findingsRefinements",
            body=body,
            api_version="v1alpha",
        )
        name_res = str(resp.get("name", ""))
        created_id = name_res.split("/")[-1] if "/" in name_res else exclusion.id

        dep_body: dict[str, object] = {
            "enabled": True,
            "archived": False,
        }
        app: dict[str, list[str]] = {}
        if exclusion.ruleset_id:
            cat = self._category_cache.get(exclusion.ruleset_id, "-")
            curated_res = (
                f"projects/{self._client._config.project}/locations/{self._client._config.location}/"
                f"instances/{self._client._config.instance_id}/curatedRuleSetCategories/{cat}/"
                f"curatedRuleSets/{exclusion.ruleset_id}"
            )
            app["curatedRuleSets"] = [curated_res]
        if exclusion.rule_id:
            rule_res = (
                f"projects/{self._client._config.project}/locations/{self._client._config.location}/"
                f"instances/{self._client._config.instance_id}/rules/{exclusion.rule_id}"
            )
            app["rules"] = [rule_res]
        if app:
            dep_body["detectionExclusionApplication"] = app

        logger.info("Configuring findings refinement deployment for '%s'", created_id)
        try:
            self._client.request(
                "PATCH",
                f"findingsRefinements/{created_id}/deployment",
                body=dep_body,
                params={"updateMask": "enabled,archived,detectionExclusionApplication"},
                api_version="v1alpha",
            )
        except Exception:
            logger.warning(
                "Findings refinement '%s' was created on tenant (id=%s), "
                "but configuring deployment failed",
                exclusion.id,
                created_id,
            )
            raise
        return created_id

    def update_exclusion(self, exclusion: ManagedExclusion) -> None:
        body: dict[str, object] = {
            "displayName": exclusion.description,
            "query": exclusion.expression,
        }
        logger.info("Updating findings refinement '%s'", exclusion.id)
        self._client.request(
            "PATCH",
            f"findingsRefinements/{exclusion.id}",
            body=body,
            params={"updateMask": "displayName,query"},
            api_version="v1alpha",
        )

        dep_body: dict[str, object] = {
            "enabled": True,
            "archived": False,
        }
        app: dict[str, list[str]] = {}
        if exclusion.ruleset_id:
            cat = self._category_cache.get(exclusion.ruleset_id, "-")
            curated_res = (
                f"projects/{self._client._config.project}/locations/{self._client._config.location}/"
                f"instances/{self._client._config.instance_id}/curatedRuleSetCategories/{cat}/"
                f"curatedRuleSets/{exclusion.ruleset_id}"
            )
            app["curatedRuleSets"] = [curated_res]
        if exclusion.rule_id:
            rule_res = (
                f"projects/{self._client._config.project}/locations/{self._client._config.location}/"
                f"instances/{self._client._config.instance_id}/rules/{exclusion.rule_id}"
            )
            app["rules"] = [rule_res]
        if app:
            dep_body["detectionExclusionApplication"] = app

        logger.info("Updating findings refinement deployment for '%s'", exclusion.id)
        try:
            self._client.request(
                "PATCH",
                f"findingsRefinements/{exclusion.id}/deployment",
                body=dep_body,
                params={"updateMask": "enabled,archived,detectionExclusionApplication"},
                api_version="v1alpha",
            )
        except Exception:
            logger.warning(
                "Findings refinement '%s' definition was updated on tenant, "
                "but configuring deployment failed",
                exclusion.id,
            )
            raise

    def delete_exclusion(self, exclusion_id: str) -> None:
        logger.info(
            "Retiring findings refinement exclusion '%s' by disabling and archiving deployment",
            exclusion_id,
        )
        self._client.request(
            "PATCH",
            f"findingsRefinements/{exclusion_id}/deployment",
            body={"enabled": False, "archived": True},
            params={"updateMask": "enabled,archived"},
            api_version="v1alpha",
        )

    def apply_managed_state(self, target_state: ManagedState) -> None:
        # Import lazily or at top level from core
        from graft.core.reconciler import GitOpsReconciler

        reconciler = GitOpsReconciler()
        reconciler.apply(desired=target_state, port=self)
