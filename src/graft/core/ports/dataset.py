from typing import Protocol, runtime_checkable

from graft.core.models.dataset import DatasetEnvelope


@runtime_checkable
class DatasetPort(Protocol):
    def list_datasets(
        self,
        names: tuple[str, ...] | None = None,
    ) -> tuple[DatasetEnvelope, ...]: ...

    def create_dataset(self, dataset: DatasetEnvelope) -> str: ...

    def update_dataset(self, dataset: DatasetEnvelope) -> None: ...
