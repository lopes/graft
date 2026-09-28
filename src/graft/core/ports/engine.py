from pathlib import Path
from typing import Protocol, runtime_checkable

from graft.core.models.managed import ManagedState
from graft.core.models.rule import RuleEnvelope
from graft.core.ports.compiler import RuleCompilerPort
from graft.core.ports.deployer import RuleDeployerPort
from graft.core.ports.managed import ManagedEnginePort
from graft.core.ports.replay import ReplayHarnessPort


@runtime_checkable
class EngineAdapter(Protocol):
    def __init__(self, env: str = "production") -> None: ...

    def get_compiler(self) -> RuleCompilerPort | None: ...

    def get_deployer(self) -> RuleDeployerPort | None: ...

    def get_managed(self) -> ManagedEnginePort | None: ...

    def get_replay(self) -> ReplayHarnessPort | None: ...

    def resolve_deployment_status(self, rule: RuleEnvelope) -> str:
        if not rule.deployment.enabled:
            return "disabled"
        return "enabled" if rule.deployment.alerting else "silent"

    def are_rules_equal(self, desired: RuleEnvelope, remote: RuleEnvelope) -> bool:
        return desired.logic.strip() == remote.logic.strip()

    def deconstruct_rule(self, remote_rule: RuleEnvelope) -> RuleEnvelope:
        return remote_rule

    def load_managed_manifest(self, path: Path) -> ManagedState | None:
        return None

    def dump_managed_manifest(self, state: ManagedState, path: Path) -> None:
        return None
