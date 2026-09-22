from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

from graft.core.models.managed import ManagedState
from graft.core.models.rule import BaseDeploymentConfig, RuleEnvelope, Runbook
from graft.core.ports.compiler import RuleCompilerPort
from graft.core.ports.deployer import RuleDeployerPort
from graft.core.ports.engine import EngineAdapter
from graft.core.ports.managed import ManagedEnginePort
from graft.core.ports.replay import ReplayHarnessPort
from graft.engines.secops.client import SecOpsClient
from graft.engines.secops.compiler import (
    SecOpsCompilerAdapter,
    deconstruct_yaral_rule,
    synthesize_yaral_rule,
)
from graft.engines.secops.config import SecOpsConfig
from graft.engines.secops.deployer import SecOpsDeployerAdapter
from graft.engines.secops.managed import SecOpsManagedAdapter
from graft.engines.secops.managed_loader import (
    dump_managed_manifest_to_yaml,
    load_managed_manifest_from_yaml,
)
from graft.engines.secops.replay import SecOpsReplayAdapter

logger = logging.getLogger("graft.secops.adapter")


def secops_rule_content_matches(desired: RuleEnvelope, remote: RuleEnvelope) -> bool:
    remote_text = remote.logic.strip().replace("\r\n", "\n")
    desired_text = desired.logic.strip().replace("\r\n", "\n")
    if remote_text == desired_text:
        return True

    synth_desired, _ = synthesize_yaral_rule(desired)
    if remote_text == synth_desired.strip().replace("\r\n", "\n"):
        return True

    try:
        remote_meta, remote_logic = deconstruct_yaral_rule(
            remote_text,
            fallback_id=remote.metadata.id,
            fallback_name=remote.metadata.name,
        )
        return bool(
            remote_meta.id == desired.metadata.id
            and remote_meta.description == desired.metadata.description
            and remote_logic.strip() == desired.logic.strip()
        )
    except Exception:
        return False


class SecOpsAdapter(EngineAdapter):
    def __init__(
        self,
        env: str = "production",
        client: SecOpsClient | None = None,
    ) -> None:
        self.env = env
        self._client: SecOpsClient | None = client
        self._compiler: SecOpsCompilerAdapter | None = None
        self._deployer: SecOpsDeployerAdapter | None = None
        self._managed: SecOpsManagedAdapter | None = None
        self._replay: SecOpsReplayAdapter | None = None

        if client is not None:
            self._init_adapters(client, config=None)
        else:
            self._try_init_from_env()

    def _try_init_from_env(self) -> None:
        target_profile: Literal["staging", "prod"] = "staging" if self.env == "staging" else "prod"
        try:
            config = SecOpsConfig.from_env(target=target_profile)
        except Exception:
            config = SecOpsConfig(project="mock", location="us", instance_id="mock")

        client = SecOpsClient(config=config)
        self._client = client
        self._init_adapters(client, config=config)

    def _init_adapters(self, client: SecOpsClient, config: SecOpsConfig | None) -> None:
        self._compiler = SecOpsCompilerAdapter(client=client)
        self._deployer = SecOpsDeployerAdapter(client=client)
        self._managed = SecOpsManagedAdapter(client=client)
        self._replay = SecOpsReplayAdapter(client=client, deployer=self._deployer, config=config)

    def get_compiler(self) -> RuleCompilerPort | None:
        return self._compiler

    def get_deployer(self) -> RuleDeployerPort | None:
        return self._deployer

    def get_managed(self) -> ManagedEnginePort | None:
        return self._managed

    def get_replay(self) -> ReplayHarnessPort | None:
        return self._replay

    def are_rules_equal(self, desired: RuleEnvelope, remote: RuleEnvelope) -> bool:
        return secops_rule_content_matches(desired, remote)

    def resolve_deployment_status(self, rule: RuleEnvelope) -> str:
        if not rule.deployment.enabled:
            return "disabled"
        if rule.deployment.alerting:
            return "enabled"
        return "silent"

    def load_managed_manifest(self, path: Path) -> ManagedState:
        return load_managed_manifest_from_yaml(path)

    def dump_managed_manifest(self, state: ManagedState, path: Path) -> None:
        dump_managed_manifest_to_yaml(state, path)

    def deconstruct_rule(self, remote_rule: RuleEnvelope) -> RuleEnvelope:
        metadata, logic = deconstruct_yaral_rule(
            rule_text=remote_rule.logic,
            fallback_id=remote_rule.metadata.id,
            fallback_name=remote_rule.metadata.name,
        )
        deployment = BaseDeploymentConfig(
            enabled=remote_rule.deployment.enabled,
            alerting=remote_rule.deployment.alerting,
            run_frequency="live",
        )
        runbook = Runbook(
            context=f"Imported from Google SecOps tenant for detection {metadata.name}.",
            triage=(
                "1. Review alert details and principal entities.\n"
                "2. Correlate with adjacent telemetry."
            ),
            response=(
                "1. Follow organizational incident response playbooks.\n"
                "2. Remediate or isolate impacted credentials/hosts."
            ),
        )
        return RuleEnvelope(
            metadata=metadata,
            logic=logic,
            deployment=deployment,
            runbook=runbook,
            tests=(),
        )
