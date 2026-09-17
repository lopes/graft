from typing import Protocol

from graft.core.models.managed import ManagedState


class ManagedEnginePort(Protocol):
    def fetch_managed_state(self) -> ManagedState: ...

    def apply_managed_state(self, target_state: ManagedState) -> None: ...

    def set_ruleset_deployment(
        self, ruleset_id: str, deployment_type: str, enabled: bool, alerting: bool
    ) -> None: ...
