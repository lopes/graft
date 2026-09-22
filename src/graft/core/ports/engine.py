from typing import Protocol, runtime_checkable

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

    def resolve_deployment_status(self, rule: RuleEnvelope) -> str: ...
