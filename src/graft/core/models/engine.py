from dataclasses import dataclass, field


@dataclass(frozen=True)
class EngineCapabilities:
    custom_rules: bool = True
    datasets: bool = False
    syntax_verification: bool = False
    managed_rules: bool = False
    replay_testing: bool = False


@dataclass(frozen=True)
class EngineManifest:
    name: str
    display_name: str
    description: str
    adapter_class: str
    capabilities: EngineCapabilities
    environments: tuple[str, ...] = ("staging", "production")
    required_env_vars: tuple[str, ...] = field(default_factory=tuple)
    optional_env_vars: tuple[str, ...] = field(default_factory=tuple)
