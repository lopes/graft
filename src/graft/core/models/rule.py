from dataclasses import dataclass, field


@dataclass(frozen=True)
class RuleMetadata:
    id: str
    name: str
    description: str
    status: str
    priority: str | None = None
    authors: tuple[str, ...] = ()
    mitre: dict[str, tuple[str, ...]] = field(default_factory=dict)
    tags: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    created_at: str | None = None
    updated_at: str | None = None


@dataclass(frozen=True)
class BaseDeploymentConfig:
    enabled: bool = True
    alerting: bool = True


@dataclass(frozen=True)
class Runbook:
    context: str = ""
    triage: str = ""
    response: str = ""


@dataclass(frozen=True)
class TestEvent:
    __test__ = False
    timestamp: str
    data: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class TestExpectation:
    __test__ = False
    alerts: int = 1


@dataclass(frozen=True)
class TestVector:
    __test__ = False
    id: str
    description: str = ""
    events: tuple[TestEvent, ...] = ()
    expect: TestExpectation = field(default_factory=TestExpectation)


@dataclass(frozen=True)
class RuleEnvelope:
    metadata: RuleMetadata
    logic: str
    deployment: BaseDeploymentConfig
    runbook: Runbook
    tests: tuple[TestVector, ...] = ()
