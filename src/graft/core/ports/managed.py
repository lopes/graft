from typing import Protocol

from graft.core.models.managed import ManagedExclusion, ManagedState


class ManagedEnginePort(Protocol):
    def fetch_managed_state(self) -> ManagedState: ...

    def apply_managed_state(self, target_state: ManagedState) -> None: ...

    def set_ruleset_deployment(
        self,
        ruleset_id: str,
        deployment_type: str,
        enabled: bool,
        alerting: bool,
        category: str | None = None,
    ) -> None: ...

    def create_exclusion(self, exclusion: ManagedExclusion) -> str: ...

    def update_exclusion(self, exclusion: ManagedExclusion) -> None: ...

    def delete_exclusion(self, exclusion_id: str) -> None: ...
