from dataclasses import dataclass, field


@dataclass(frozen=True)
class ManagedDeployment:
    type: str
    enabled: bool
    alerting: bool


@dataclass(frozen=True)
class ManagedRuleSet:
    id: str
    name: str
    category: str
    deployments: tuple[ManagedDeployment, ...]
    category_id: str = field(default="", compare=False)


@dataclass(frozen=True)
class ManagedExclusion:
    id: str
    rule_id: str | None
    ruleset_id: str | None
    expression: str
    description: str = ""


@dataclass(frozen=True)
class ManagedState:
    rulesets: tuple[ManagedRuleSet, ...]
    exclusions: tuple[ManagedExclusion, ...] = ()
