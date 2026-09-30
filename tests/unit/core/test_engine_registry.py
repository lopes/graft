from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from graft.core.engine_registry import EngineManifestLoadError, EngineNotFoundError, EngineRegistry
from graft.core.models.engine import EngineCapabilities, EngineManifest
from graft.core.models.rule import RuleEnvelope
from graft.core.ports.compiler import RuleCompilerPort
from graft.core.ports.deployer import RuleDeployerPort
from graft.core.ports.engine import EngineAdapter
from graft.core.ports.managed import ManagedEnginePort
from graft.core.ports.replay import ReplayHarnessPort


def test_engine_capabilities_defaults() -> None:
    caps = EngineCapabilities(custom_rules=True)
    assert caps.custom_rules is True
    assert caps.syntax_verification is False
    assert caps.managed_rules is False
    assert caps.replay_testing is False


def test_engine_manifest_immutability() -> None:
    manifest = EngineManifest(
        name="test_engine",
        display_name="Test Engine",
        description="A test engine adapter",
        adapter_class="graft.engines.test.adapter:TestAdapter",
        capabilities=EngineCapabilities(custom_rules=True, syntax_verification=True),
        environments=("staging", "production"),
        required_env_vars=("TEST_KEY",),
        optional_env_vars=("TEST_REGION",),
    )
    assert manifest.name == "test_engine"
    assert manifest.capabilities.syntax_verification is True

    with pytest.raises(FrozenInstanceError):
        manifest.name = "changed"  # type: ignore[misc]


def test_engine_registry_discover_valid_engine(tmp_path: Path) -> None:
    engine_dir = tmp_path / "mock_engine"
    engine_dir.mkdir(parents=True)
    manifest_file = engine_dir / "engine.yaml"
    manifest_file.write_text(
        """name: mock_engine
display_name: Mock SIEM Engine
description: Mock engine for registry test
adapter_class: graft.mock:MockAdapter
capabilities:
  custom_rules: true
  syntax_verification: true
  managed_rules: false
  replay_testing: false
environments:
  - staging
  - production
env_vars:
  required:
    - MOCK_API_KEY
  optional:
    - MOCK_REGION
""",
        encoding="utf-8",
    )

    registry = EngineRegistry(engines_dir=tmp_path)
    manifests = registry.list_engines()
    assert len(manifests) == 1
    assert manifests[0].name == "mock_engine"
    assert manifests[0].display_name == "Mock SIEM Engine"
    assert manifests[0].capabilities.custom_rules is True
    assert manifests[0].capabilities.syntax_verification is True
    assert manifests[0].capabilities.managed_rules is False
    assert manifests[0].required_env_vars == ("MOCK_API_KEY",)

    fetched = registry.get("mock_engine")
    assert fetched.name == "mock_engine"


def test_engine_registry_get_nonexistent_raises(tmp_path: Path) -> None:
    registry = EngineRegistry(engines_dir=tmp_path)
    with pytest.raises(EngineNotFoundError, match="Engine 'unknown' not found"):
        registry.get("unknown")


def test_engine_registry_rejects_invalid_manifest(tmp_path: Path) -> None:
    engine_dir = tmp_path / "bad_engine"
    engine_dir.mkdir(parents=True)
    manifest_file = engine_dir / "engine.yaml"
    manifest_file.write_text(
        """name: Bad-Name!
display_name: Bad Engine
description: Short
capabilities: {}
""",
        encoding="utf-8",
    )

    registry = EngineRegistry(engines_dir=tmp_path)
    with pytest.raises(EngineManifestLoadError):
        registry.get("bad_engine")


def test_engine_registry_rejects_reserved_command_name(tmp_path: Path) -> None:
    engine_dir = tmp_path / "lint"
    engine_dir.mkdir(parents=True)
    manifest_file = engine_dir / "engine.yaml"
    manifest_file.write_text(
        """name: lint
display_name: Lint Engine
description: Hijacks core lint
adapter_class: graft.mock:MockAdapter
capabilities:
  custom_rules: true
""",
        encoding="utf-8",
    )

    registry = EngineRegistry(engines_dir=tmp_path)
    with pytest.raises(EngineManifestLoadError, match="reserved 1st-order command"):
        registry.get("lint")


class DummyAdapter(EngineAdapter):
    def __init__(self, env: str = "production") -> None:
        self.env = env

    def get_compiler(self) -> RuleCompilerPort | None:
        return None

    def get_deployer(self) -> RuleDeployerPort | None:
        return None

    def get_managed(self) -> ManagedEnginePort | None:
        return None

    def get_replay(self) -> ReplayHarnessPort | None:
        return None

    def resolve_deployment_status(
        self,
        rule: RuleEnvelope,
        managed_state: object = None,
    ) -> str:
        return "enabled" if rule.deployment.enabled else "disabled"


def test_engine_adapter_protocol_conformance(tmp_path: Path) -> None:
    from graft.core.models.rule import BaseDeploymentConfig, RuleMetadata, Runbook

    adapter = DummyAdapter(env="staging")
    assert isinstance(adapter, EngineAdapter)
    assert adapter.get_compiler() is None
    assert adapter.get_deployer() is None
    assert adapter.get_managed() is None
    assert adapter.get_replay() is None

    dummy_rule = RuleEnvelope(
        metadata=RuleMetadata(
            id="00000000-0000-0000-0000-000000000001",
            name="test_rule",
            description="desc",
        ),
        logic="events: $e condition: $e",
        deployment=BaseDeploymentConfig(enabled=True, alerting=False),
        runbook=Runbook(),
        tests=(),
    )
    assert adapter.are_rules_equal(dummy_rule, dummy_rule) is True
    assert adapter.deconstruct_rule(dummy_rule) == dummy_rule
    assert adapter.load_managed_manifest(tmp_path / "index.yaml") is None


def test_engine_registry_loads_adapter_class(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys
    import types

    mock_mod = types.ModuleType("mock_adapter_module")
    mock_mod.DummyAdapter = DummyAdapter  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "mock_adapter_module", mock_mod)

    engine_dir = tmp_path / "dummy_engine"
    engine_dir.mkdir(parents=True)
    manifest_file = engine_dir / "engine.yaml"
    manifest_file.write_text(
        """name: dummy_engine
display_name: Dummy Engine
description: Dummy engine description
adapter_class: mock_adapter_module:DummyAdapter
capabilities:
  custom_rules: true
""",
        encoding="utf-8",
    )

    registry = EngineRegistry(engines_dir=tmp_path)
    adapter = registry.load_adapter("dummy_engine", env="staging")
    assert isinstance(adapter, DummyAdapter)
    assert adapter.env == "staging"
