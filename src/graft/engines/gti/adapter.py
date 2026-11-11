from __future__ import annotations

from typing import Literal

from graft.core.models.managed import ManagedState
from graft.core.models.rule import RuleEnvelope
from graft.core.ports.compiler import RuleCompilerPort
from graft.core.ports.dataset import DatasetPort
from graft.core.ports.deployer import RuleDeployerPort
from graft.core.ports.engine import EngineAdapter
from graft.core.ports.managed import ManagedEnginePort
from graft.core.ports.replay import ReplayHarnessPort
from graft.engines.gti.client import GTIClient
from graft.engines.gti.compiler import (
    GTICompilerAdapter,
    deconstruct_yara_rule,
    synthesize_yara_rule,
    validate_gti_dataset_references,
)
from graft.engines.gti.config import GTIConfig
from graft.engines.gti.deployer import (
    GTIDeployerAdapter,
    normalize_gti_deployment,
    resolve_gti_deployment_type,
)
from graft.engines.gti.replay import GTIReplayAdapter


class GTIAdapter(EngineAdapter):
    def __init__(self, env: str = "production") -> None:
        self._env = env
        target: Literal["staging", "prod"] = "staging" if env == "staging" else "prod"
        try:
            self._config: GTIConfig | None = GTIConfig.from_env(target)
            self._client: GTIClient | None = GTIClient(self._config)
        except (KeyError, ValueError):
            self._config = None
            self._client = None

        self._compiler = GTICompilerAdapter(client=self._client)
        self._deployer: GTIDeployerAdapter | None = (
            GTIDeployerAdapter(client=self._client) if self._client is not None else None
        )
        self._replay = GTIReplayAdapter(client=self._client)

    def get_compiler(self) -> RuleCompilerPort | None:
        return self._compiler

    def get_deployer(self) -> RuleDeployerPort | None:
        if self._deployer is None:
            fallback_cfg = GTIConfig(api_key="unconfigured")
            self._deployer = GTIDeployerAdapter(client=GTIClient(fallback_cfg))
        return self._deployer

    def get_managed(self) -> ManagedEnginePort | None:
        return None

    def get_replay(self) -> ReplayHarnessPort | None:
        return self._replay

    def get_dataset(self) -> DatasetPort | None:
        return None

    def resolve_deployment_status(
        self,
        rule: RuleEnvelope,
        managed_state: ManagedState | None = None,
    ) -> str:
        if rule.is_managed:
            return "disabled"
        if not bool(rule.deployment.get("enabled", True)):
            return "disabled"
        emails = rule.deployment.get("notification_emails")
        if isinstance(emails, (list, tuple)) and len(emails) == 0:
            return "silent"
        return "enabled"

    def are_rules_equal(self, desired: RuleEnvelope, remote: RuleEnvelope) -> bool:
        des_yara, _ = synthesize_yara_rule(desired)
        rem_yara, _ = synthesize_yara_rule(remote)
        return des_yara.strip() == rem_yara.strip()

    def are_deployments_equal(self, desired: RuleEnvelope, remote: RuleEnvelope) -> bool:
        default_emails = self._config.notification_emails if self._config is not None else ()
        return normalize_gti_deployment(desired, default_emails) == normalize_gti_deployment(
            remote, default_emails
        )

    def should_deploy_rule(self, rule: RuleEnvelope) -> bool:
        if resolve_gti_deployment_type(rule) == "retrohunt":
            return bool(rule.deployment.get("enabled", False))
        return True

    def render_rule(self, rule: RuleEnvelope) -> str:
        rendered, _ = synthesize_yara_rule(rule)
        return rendered

    def deconstruct_rule(self, remote_rule: RuleEnvelope) -> RuleEnvelope:
        return deconstruct_yara_rule(remote_rule)

    def get_default_rule_logic(self, rule_name: str) -> str:
        return 'import "vt"\n\ncondition:\n  vt.net.url.new_url'

    def get_default_deployment_config(self) -> dict[str, object]:
        return {
            "type": "livehunt",
            "subtype": "url",
            "enabled": False,
            "daily_limit": 100,
        }

    def get_default_test_event_payload(self) -> dict[str, object]:
        return {"vt.net.url.new_url": True}

    def validate_rule_dataset_references(
        self,
        rule: RuleEnvelope,
        local_dataset_names: set[str],
    ) -> None:
        validate_gti_dataset_references(rule, local_dataset_names)
