from dataclasses import dataclass, field


@dataclass(frozen=True)
class RuleMetadata:
    id: str
    name: str
    description: str
    severity: str
    authors: tuple[str, ...] = ()
    mitre_attack: dict[str, tuple[str, ...]] = field(default_factory=dict)
    tags: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    created_at: str | None = None
    updated_at: str | None = None


@dataclass(frozen=True)
class BaseDeploymentConfig:
    enabled: bool = True
    alerting: bool = True


@dataclass(frozen=True)
class InvestigationGuide:
    context: str = ""
    triage_runbook: str = ""
    false_positives: tuple[str, ...] = ()
    response_playbooks: tuple[str, ...] = ()


@dataclass(frozen=True)
class TestEvent:
    __test__ = False
    timestamp: str
    data: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class TestVector:
    __test__ = False
    name: str
    description: str = ""
    events: tuple[TestEvent, ...] = ()
    expected_match: bool = True
    expected_variables: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class RuleEnvelope:
    metadata: RuleMetadata
    logic: str
    deployment: BaseDeploymentConfig
    guide: InvestigationGuide
    test: tuple[TestVector, ...] = ()
