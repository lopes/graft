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


@dataclass(frozen=True)
class BaseDeploymentConfig:
    enabled: bool = True
    alerting: bool = True
    run_frequency: str = "unspecified"


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
class RuleEnvelope:
    metadata: RuleMetadata
    logic: str
    deployment: BaseDeploymentConfig
    runbook: Runbook
    tests: tuple[TestVector, ...] = ()
