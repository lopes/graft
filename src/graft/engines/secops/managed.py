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
        response = self._client.request("GET", "curatedRuleSetCategories/-/curatedRuleSets")
        raw_rulesets = response.get("curatedRuleSets", [])
        if not isinstance(raw_rulesets, list):
            raw_rulesets = []

        rulesets: list[ManagedRuleSet] = []
        for raw in raw_rulesets:
            if not isinstance(raw, dict):
                continue
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

            self._category_cache[ruleset_id] = category

            # Fetch deployments for this curated ruleset
            deployments_path = (
                f"curatedRuleSetCategories/{category}/curatedRuleSets/"
                f"{ruleset_id}/curatedRuleSetDeployments"
            )
            deployments_resp = self._client.request("GET", deployments_path)
            raw_deployments = deployments_resp.get("curatedRuleSetDeployments", [])

            deployments: list[ManagedDeployment] = []
            if isinstance(raw_deployments, list):
                for dep in raw_deployments:
                    if not isinstance(dep, dict):
                        continue
                    dep_name = str(dep.get("name", ""))
                    dep_type = "PRECISE" if dep_name.lower().endswith("/precise") else "BROAD"
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

            rulesets.append(
                ManagedRuleSet(
                    id=ruleset_id,
                    name=display_name or ruleset_id,
                    category=category,
                    deployments=tuple(deployments),
                )
            )

        # Fetch exclusions (findingsRefinements)
        logger.info("Fetching findings refinements from Google SecOps API")
        excl_resp = self._client.request("GET", "findingsRefinements")
        raw_exclusions = excl_resp.get("findingsRefinements", [])
        exclusions: list[ManagedExclusion] = []

        if isinstance(raw_exclusions, list):
            for raw_ex in raw_exclusions:
                if not isinstance(raw_ex, dict):
                    continue
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
        )

    def delete_exclusion(self, exclusion_id: str) -> None:
        logger.info("Deleting findings refinement exclusion '%s'", exclusion_id)
        self._client.request("DELETE", f"findingsRefinements/{exclusion_id}")

    def apply_managed_state(self, target_state: ManagedState) -> None:
        # Import lazily or at top level from core
        from graft.core.reconciler import GitOpsReconciler

        reconciler = GitOpsReconciler()
        reconciler.apply(desired=target_state, port=self)
