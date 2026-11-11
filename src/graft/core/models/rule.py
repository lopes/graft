from collections.abc import Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True)
class RuleMetadata:
    id: str
    name: str
    description: str
    owners: tuple[str, ...] = ()
    mitre: dict[str, tuple[str, ...]] = field(default_factory=dict)
    tags: tuple[str, ...] = ()
    references: tuple[str, ...] = ()


@dataclass(frozen=True, init=False)
class BaseDeploymentConfig:
    params: dict[str, object] = field(default_factory=dict)

    def __init__(
        self,
        params: Mapping[str, object] | None = None,
        **extra: object,
    ) -> None:
        merged: dict[str, object] = {}
        if params is not None:
            merged.update(params)
        merged.update(extra)
        object.__setattr__(self, "params", merged)

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "BaseDeploymentConfig":
        return cls(params=dict(data))

    def to_dict(self) -> dict[str, object]:
        return dict(self.params)

    def get(self, key: str, default: object = None) -> object:
        return self.params.get(key, default)

    def __getitem__(self, key: str) -> object:
        return self.params[key]

    def __contains__(self, key: object) -> bool:
        return key in self.params

    def __getattr__(self, name: str) -> object:
        if name in self.params:
            return self.params[name]
        raise AttributeError(f"'{type(self).__name__}' has no deployment parameter '{name}'")


@dataclass(frozen=True)
class Runbook:
    context: str = ""
    triage: str = ""
    response: str = ""


@dataclass(frozen=True)
class TestEvent:
    __test__ = False
    timestamp: str
    payload: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class TestVector:
    __test__ = False
    id: str
    description: str = ""
    expect: int = 1
    events: tuple[TestEvent, ...] = ()


@dataclass(frozen=True)
class ManagedRuleRef:
    id: str


@dataclass(frozen=True)
class RuleEnvelope:
    metadata: RuleMetadata
    logic: str = ""
    deployment: BaseDeploymentConfig = field(default_factory=BaseDeploymentConfig)
    runbook: Runbook = field(default_factory=Runbook)
    tests: tuple[TestVector, ...] = ()
    managed: ManagedRuleRef | None = None

    @property
    def is_managed(self) -> bool:
        return self.managed is not None

    @property
    def rule_type(self) -> str:
        return "managed" if self.managed is not None else "custom"
