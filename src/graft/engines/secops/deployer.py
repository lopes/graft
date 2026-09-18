from graft.core.models.rule import BaseDeploymentConfig, RuleEnvelope, RuleMetadata, Runbook
from graft.core.ports.deployer import RuleDeployerPort
from graft.engines.secops.client import SecOpsApiError, SecOpsClient
from graft.engines.secops.compiler import synthesize_yaral_rule


class SecOpsDeployerAdapter(RuleDeployerPort):
    def __init__(self, client: SecOpsClient) -> None:
        self._client = client

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

        envelopes: list[RuleEnvelope] = []
        for raw in raw_rules:
            if not isinstance(raw, dict):
                continue
            name_resource = str(raw.get("name", ""))
            rule_id = name_resource.split("/")[-1] if "/" in name_resource else name_resource
            display_name = str(raw.get("displayName", rule_id))
            text = str(raw.get("text", ""))

            dep_enabled, dep_alerting = deployments_map.get(rule_id, (False, False))

            metadata = RuleMetadata(
                id=rule_id,
                name=display_name,
                description="",
                status="production",
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
        rule_id = resource_name.split("/")[-1] if "/" in resource_name else resource_name

        self.set_rule_state(
            rule_id=rule_id,
            enabled=rule.deployment.enabled,
            alerting=rule.deployment.alerting,
        )
        return rule_id

    def update_rule(self, rule: RuleEnvelope) -> None:
        rule_text, _ = synthesize_yaral_rule(rule)
        rule_id = rule.metadata.id
        self._client.request(
            "PATCH",
            f"rules/{rule_id}",
            body={"text": rule_text},
            params={"update_mask": "text"},
        )
        self.set_rule_state(
            rule_id=rule_id,
            enabled=rule.deployment.enabled,
            alerting=rule.deployment.alerting,
        )

    def delete_rule(self, rule_id: str) -> None:
        self._client.request("DELETE", f"rules/{rule_id}")

    def set_rule_state(self, rule_id: str, enabled: bool, alerting: bool) -> None:
        self._client.request(
            "PATCH",
            f"rules/{rule_id}/deployment",
            body={"enabled": enabled, "alerting": alerting},
            params={"update_mask": "enabled,alerting"},
        )
