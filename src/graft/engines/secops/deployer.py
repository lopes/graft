from graft.core.models.rule import BaseDeploymentConfig, RuleEnvelope, RuleMetadata, Runbook
from graft.core.ports.deployer import RuleDeployerPort
from graft.engines.secops.client import SecOpsApiError, SecOpsClient
from graft.engines.secops.compiler import extract_meta_id, synthesize_yaral_rule


class SecOpsDeployerAdapter(RuleDeployerPort):
    def __init__(self, client: SecOpsClient) -> None:
        self._client = client
        self._remote_ids_by_name: dict[str, str] = {}
        self._remote_ids_by_meta_id: dict[str, str] = {}

    def _resolve_remote_id(self, rule_id: str, rule_name: str = "") -> str:
        if rule_id.startswith("ru_"):
            return rule_id
        if rule_id in self._remote_ids_by_meta_id:
            return self._remote_ids_by_meta_id[rule_id]
        if rule_name and rule_name in self._remote_ids_by_name:
            return self._remote_ids_by_name[rule_name]
        return rule_id

    def list_rules(self) -> tuple[RuleEnvelope, ...]:
        response = self._client.request("GET", "rules", params={"view": "FULL"})
        raw_rules = response.get("rules")
        if not isinstance(raw_rules, list):
            return ()

        deployments_map: dict[str, tuple[bool, bool]] = {}
        try:
            dep_response = self._client.request("GET", "rules/-/deployments")
            raw_deps = dep_response.get("ruleDeployments")
            if isinstance(raw_deps, list):
                for dep in raw_deps:
                    if not isinstance(dep, dict):
                        continue
                    name_resource = str(dep.get("name", ""))
                    dep_rule_id = (
                        name_resource.split("/")[-2]
                        if "/deployment" in name_resource
                        else name_resource.split("/")[-1]
                    )
                    enabled = bool(dep.get("enabled", False))
                    alerting = bool(dep.get("alerting", False))
                    deployments_map[dep_rule_id] = (enabled, alerting)
        except SecOpsApiError:
            pass

        self._remote_ids_by_name.clear()
        self._remote_ids_by_meta_id.clear()

        envelopes: list[RuleEnvelope] = []
        for raw in raw_rules:
            if not isinstance(raw, dict):
                continue
            name_resource = str(raw.get("name", ""))
            secops_id = name_resource.split("/")[-1] if "/" in name_resource else name_resource
            display_name = str(raw.get("displayName", secops_id))
            text = str(raw.get("text", ""))

            dep_enabled, dep_alerting = deployments_map.get(secops_id, (False, False))

            meta_id = extract_meta_id(text)
            effective_id = meta_id or secops_id

            self._remote_ids_by_name[display_name] = secops_id
            self._remote_ids_by_meta_id[secops_id] = secops_id
            if meta_id:
                self._remote_ids_by_meta_id[meta_id] = secops_id

            metadata = RuleMetadata(
                id=effective_id,
                name=display_name,
                description="",
                authors=(),
                mitre={},
            )
            deployment = BaseDeploymentConfig(enabled=dep_enabled, alerting=dep_alerting)
            runbook = Runbook(context="", triage="", response="")
            envelopes.append(
                RuleEnvelope(
                    metadata=metadata,
                    logic=text,
                    deployment=deployment,
                    runbook=runbook,
                    tests=(),
                )
            )

        return tuple(envelopes)

    def create_rule(self, rule: RuleEnvelope) -> str:
        rule_text, _ = synthesize_yaral_rule(rule)
        response = self._client.request(
            "POST",
            "rules",
            body={"text": rule_text},
        )
        resource_name = str(response.get("name", ""))
        secops_id = resource_name.split("/")[-1] if "/" in resource_name else resource_name

        self._remote_ids_by_name[rule.metadata.name] = secops_id
        self._remote_ids_by_meta_id[rule.metadata.id] = secops_id
        self._remote_ids_by_meta_id[secops_id] = secops_id

        self.set_rule_state(
            rule_id=secops_id,
            enabled=rule.deployment.enabled,
            alerting=rule.deployment.alerting,
        )
        return secops_id

    def update_rule(self, rule: RuleEnvelope) -> None:
        rule_text, _ = synthesize_yaral_rule(rule)
        secops_id = self._resolve_remote_id(rule.metadata.id, rule.metadata.name)
        self._client.request(
            "PATCH",
            f"rules/{secops_id}",
            body={"text": rule_text},
            params={"update_mask": "text"},
        )
        self.set_rule_state(
            rule_id=secops_id,
            enabled=rule.deployment.enabled,
            alerting=rule.deployment.alerting,
        )
        self._remote_ids_by_name[rule.metadata.name] = secops_id
        self._remote_ids_by_meta_id[rule.metadata.id] = secops_id
        self._remote_ids_by_meta_id[secops_id] = secops_id

    def delete_rule(self, rule_id: str) -> None:
        target_id = self._resolve_remote_id(rule_id)
        self._client.request("DELETE", f"rules/{target_id}")

    def set_rule_state(self, rule_id: str, enabled: bool, alerting: bool) -> None:
        target_id = self._resolve_remote_id(rule_id)
        self._client.request(
            "PATCH",
            f"rules/{target_id}/deployment",
            body={"enabled": enabled, "alerting": alerting},
            params={"update_mask": "enabled,alerting"},
        )
