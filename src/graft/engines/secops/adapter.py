from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Literal

from graft.core.models.managed import ManagedState
from graft.core.models.rule import BaseDeploymentConfig, RuleEnvelope, Runbook
from graft.core.ports.compiler import RuleCompilerPort
from graft.core.ports.dataset import DatasetPort
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
from graft.engines.secops.datasets import SecOpsDatasetAdapter
from graft.engines.secops.deployer import SecOpsDeployerAdapter
from graft.engines.secops.managed import SecOpsManagedAdapter
from graft.engines.secops.managed_loader import (
    dump_managed_manifest_to_yaml,
    load_managed_manifest_from_yaml,
)
from graft.engines.secops.replay import SecOpsReplayAdapter

logger = logging.getLogger("graft.secops.adapter")

_DATASET_REF_RE = re.compile(r"%(?P<name>[a-zA-Z0-9_]+)(?:\.(?P<col>[a-zA-Z0-9_]+))?")


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
        self._datasets: SecOpsDatasetAdapter | None = None
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
        self._datasets = SecOpsDatasetAdapter(client=client)
        self._managed = SecOpsManagedAdapter(client=client)
        self._replay = SecOpsReplayAdapter(
            client=client,
            deployer=self._deployer,
            datasets=self._datasets,
            config=config,
        )

    def get_compiler(self) -> RuleCompilerPort | None:
        return self._compiler

    def get_deployer(self) -> RuleDeployerPort | None:
        return self._deployer

    def get_managed(self) -> ManagedEnginePort | None:
        return self._managed

    def get_replay(self) -> ReplayHarnessPort | None:
        return self._replay

    def get_dataset(self) -> DatasetPort | None:
        return self._datasets

    def are_rules_equal(self, desired: RuleEnvelope, remote: RuleEnvelope) -> bool:
        return secops_rule_content_matches(desired, remote)

    def resolve_deployment_status(
        self,
        rule: RuleEnvelope,
        managed_state: ManagedState | None = None,
    ) -> str:
        if rule.managed is not None:
            if managed_state is None:
                return "disabled"
            for rs in managed_state.rulesets:
                if rs.id == rule.managed.id:
                    if any(d.enabled and d.alerting for d in rs.deployments):
                        return "enabled"
                    if any(d.enabled and not d.alerting for d in rs.deployments):
                        return "silent"
                    return "disabled"
            return "disabled"
        if not rule.deployment.enabled:
            return "disabled"
        if rule.deployment.alerting:
            return "enabled"
        return "silent"

    def has_managed_rule_id(self, managed_id: str, state: ManagedState) -> bool:
        return any(rs.id == managed_id for rs in state.rulesets)

    def load_managed_manifest(self, path: Path) -> ManagedState:
        return load_managed_manifest_from_yaml(path)

    def dump_managed_manifest(self, state: ManagedState, path: Path) -> None:
        dump_managed_manifest_to_yaml(state, path)

    def get_default_rule_logic(self, rule_name: str) -> str:
        return """events:
  $e.metadata.event_type = "USER_LOGIN"
condition:
  $e"""

    def validate_rule_dataset_references(
        self,
        rule: RuleEnvelope,
        local_dataset_names: set[str],
    ) -> None:
        if not rule.logic or not local_dataset_names:
            return
        uncommented_lines = [re.sub(r"//.*$", "", line) for line in rule.logic.splitlines()]
        uncommented_logic = "\n".join(uncommented_lines)
        uncommented_logic = re.sub(r"/\*.*?\*/", "", uncommented_logic, flags=re.DOTALL)

        for match in _DATASET_REF_RE.finditer(uncommented_logic):
            ds_name = match.group("name")
            if ds_name not in local_dataset_names:
                continue
            col = match.group("col")
            if col != "value":
                raise ValueError(
                    f"Rule '{rule.metadata.name}' references local dataset '{ds_name}' as "
                    f"'{match.group(0)}'; Graft datasets are single-column string lists and "
                    f"must be referenced as '%{ds_name}.value'"
                )
            op_match = re.search(
                rf"\bin\s+(?P<op>cidr|regex)\s+%{re.escape(ds_name)}(?:\.[a-zA-Z0-9_]+)?\b",
                uncommented_logic,
                flags=re.IGNORECASE,
            )
            if op_match:
                op = op_match.group("op")
                raise ValueError(
                    f"Rule '{rule.metadata.name}' uses 'in {op}' with local dataset "
                    f"'%{ds_name}.value'; Graft datasets are literal string lists and only "
                    f"support string membership ('in %{ds_name}.value')"
                )

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
