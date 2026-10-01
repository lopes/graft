from dataclasses import dataclass, field


@dataclass(frozen=True)
class DatasetMetadata:
    name: str
    description: str
    owners: tuple[str, ...] = field(default_factory=tuple)
    tags: tuple[str, ...] = field(default_factory=tuple)
    references: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class DatasetEnvelope:
    metadata: DatasetMetadata
    values: tuple[str, ...] = field(default_factory=tuple)
