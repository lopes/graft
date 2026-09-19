import argparse
from pathlib import Path

import pytest

from graft.cli.engine_controller import register_engine_commands
from graft.core.engine_registry import EngineRegistry
from graft.core.loader import load_rule_from_yaml
from graft.core.models.compiler import CompilationResult
from graft.core.models.engine import EngineCapabilities, EngineManifest
from graft.core.models.managed import ManagedState
from graft.core.models.rule import RuleEnvelope
from graft.core.ports.compiler import RuleCompilerPort
from graft.core.ports.deployer import RuleDeployerPort
from graft.core.ports.engine import EngineAdapter
from graft.core.ports.managed import ManagedEnginePort
from graft.core.ports.replay import ReplayHarnessPort, ReplayResult


class MockCompilerAdapter(RuleCompilerPort):
    def verify_syntax(self, rule_text: str) -> CompilationResult:
        if "syntax_error" in rule_text:
            return CompilationResult(success=False, diagnostics=())
        return CompilationResult(success=True)


class MockDeployerAdapter(RuleDeployerPort):
    def __init__(self) -> None:
        self.created: list[RuleEnvelope] = []
        self.updated: list[RuleEnvelope] = []
        self.deleted: list[str] = []

    def list_rules(self) -> tuple[RuleEnvelope, ...]:
        return ()

    def create_rule(self, rule: RuleEnvelope) -> str:
        self.created.append(rule)
        return rule.metadata.id

    def update_rule(self, rule: RuleEnvelope) -> None:
        self.updated.append(rule)

    def delete_rule(self, rule_id: str) -> None:
        self.deleted.append(rule_id)

    def set_rule_state(self, rule_id: str, enabled: bool, alerting: bool) -> None:
        pass


class MockManagedAdapter(ManagedEnginePort):
    def fetch_managed_state(self) -> ManagedState:
        return ManagedState(rulesets=(), exclusions=())

    def apply_managed_state(self, target_state: ManagedState) -> None:
        pass

    def set_ruleset_deployment(
        self,
        ruleset_id: str,
        deployment_type: str,
        enabled: bool,
        alerting: bool,
        category: str | None = None,
    ) -> None:
        pass

    def create_exclusion(self, exclusion: object) -> str:
        return "ex-1"

    def update_exclusion(self, exclusion: object) -> None:
        pass

    def delete_exclusion(self, exclusion_id: str) -> None:
        pass


class MockReplayAdapter(ReplayHarnessPort):
    def run_test_vector(self, rule: RuleEnvelope, vector: object) -> ReplayResult:
        return ReplayResult(test_id="test_1", passed=True)

    def is_available(self) -> bool:
        return True


class FullMockAdapter(EngineAdapter):
    def __init__(self, env: str = "production") -> None:
        self.env = env
        self.compiler = MockCompilerAdapter()
        self.deployer = MockDeployerAdapter()
        self.managed = MockManagedAdapter()
        self.replay = MockReplayAdapter()

    def get_compiler(self) -> RuleCompilerPort | None:
        return self.compiler

    def get_deployer(self) -> RuleDeployerPort | None:
        return self.deployer

    def get_managed(self) -> ManagedEnginePort | None:
        return self.managed

    def get_replay(self) -> ReplayHarnessPort | None:
        return self.replay


def test_register_engine_commands_subparsers() -> None:
    manifest = EngineManifest(
        name="test_engine",
        display_name="Test Engine",
        description="A mock test engine",
        adapter_class="mock:FullMockAdapter",
        capabilities=EngineCapabilities(
            custom_rules=True,
            syntax_verification=True,
            managed_rules=True,
            replay_testing=True,
        ),
    )

    parser = argparse.ArgumentParser(prog="graft")
    subparsers = parser.add_subparsers(dest="command")

    registry = EngineRegistry.__new__(EngineRegistry)
    registry._manifests = {"test_engine": manifest}
    registry._errors = {}

    register_engine_commands(subparsers, manifest, registry)

    # Test that parsing subcommands works
    args = parser.parse_args(["test_engine", "verify", "--env", "staging"])
    assert args.command == "test_engine"
    assert args.engine_command == "verify"
    assert args.env == "staging"

    args = parser.parse_args(["test_engine", "diff", "--target", "custom"])
    assert args.engine_command == "diff"
    assert args.target == "custom"

    args = parser.parse_args(["test_engine", "managed", "diff"])
    assert args.engine_command == "managed"
    assert args.managed_command == "diff"

    args = parser.parse_args(["test_engine", "test"])
    assert args.engine_command == "test"


def test_engine_controller_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = EngineManifest(
        name="test_engine",
        display_name="Test Engine",
        description="A mock test engine",
        adapter_class="mock:FullMockAdapter",
        capabilities=EngineCapabilities(
            custom_rules=True,
            syntax_verification=True,
            managed_rules=True,
            replay_testing=True,
        ),
    )

    registry = EngineRegistry.__new__(EngineRegistry)
    registry._manifests = {"test_engine": manifest}
    registry._errors = {}

    adapter = FullMockAdapter(env="production")
    monkeypatch.setattr(registry, "load_adapter", lambda name, env="production": adapter)

    from graft.cli.engine_controller import EngineCommandController

    controller = EngineCommandController(manifest, registry)

    # 1. new
    args_new = argparse.Namespace(
        engine_command="new", rule_name="my_rule", out=str(tmp_path / "r.yaml")
    )
    assert controller.execute(args_new) == 0
    assert (tmp_path / "r.yaml").exists()

    # 2. verify
    args_verify = argparse.Namespace(
        engine_command="verify", paths=[str(tmp_path / "r.yaml")], env="staging"
    )
    assert controller.execute(args_verify) == 0

    # 3. diff
    args_diff = argparse.Namespace(
        engine_command="diff", target="custom", all_rules=True, env="production"
    )
    monkeypatch.setattr(
        controller, "_load_custom_rules", lambda **kw: (load_rule_from_yaml(tmp_path / "r.yaml"),)
    )
    exit_code_diff = controller.execute(args_diff)
    # Drift detected because remote deployer list_rules is empty, but local has 1 rule
    assert exit_code_diff == 2

    # 4. apply
    args_apply = argparse.Namespace(
        engine_command="apply", target="custom", all_rules=True, env="production"
    )
    exit_code_apply = controller.execute(args_apply)
    assert exit_code_apply == 0
    assert len(adapter.deployer.created) == 1

    # 5. test
    args_test = argparse.Namespace(
        engine_command="test",
        paths=[str(tmp_path / "r.yaml")],
        env="staging",
        require_staging=False,
    )
    exit_code_test = controller.execute(args_test)
    assert exit_code_test == 0
