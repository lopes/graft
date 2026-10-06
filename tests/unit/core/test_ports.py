from graft.core.models.compiler import CompilationResult
from graft.core.models.managed import (
    ManagedDeployment,
    ManagedExclusion,
    ManagedRuleSet,
    ManagedState,
)
from graft.core.models.rule import (
    BaseDeploymentConfig,
    RuleEnvelope,
    RuleMetadata,
    Runbook,
    TestVector,
)
from graft.core.ports.compiler import RuleCompilerPort
from graft.core.ports.deployer import RuleDeployerPort
from graft.core.ports.managed import ManagedEnginePort
from graft.core.ports.replay import ReplayHarnessPort, ReplayResult


class MockCompiler:
    def verify_syntax(self, rule_text: str) -> CompilationResult:
        if "syntax_error" in rule_text:
            return CompilationResult(success=False)
        return CompilationResult(success=True)

    def verify_rule(self, rule: RuleEnvelope) -> CompilationResult:
        return self.verify_syntax(rule.logic)


class MockDeployer:
    def __init__(self) -> None:
        self.rules: dict[str, RuleEnvelope] = {}

    def list_rules(self) -> tuple[RuleEnvelope, ...]:
        return tuple(self.rules.values())

    def create_rule(self, rule: RuleEnvelope) -> str:
        self.rules[rule.metadata.id] = rule
        return rule.metadata.id

    def update_rule(self, rule: RuleEnvelope) -> None:
        self.rules[rule.metadata.id] = rule

    def delete_rule(self, rule_id: str) -> None:
        self.rules.pop(rule_id, None)

    def set_rule_state(self, rule_id: str, enabled: bool, alerting: bool) -> None:
        pass


class MockManagedEngine:
    def __init__(self) -> None:
        self.state = ManagedState(
            rulesets=(
                ManagedRuleSet(
                    id="rs-1",
                    name="Ruleset 1",
                    category="CATEGORY",
                    deployments=(ManagedDeployment(type="PRECISE", enabled=True, alerting=True),),
                ),
            ),
            exclusions=(),
        )

    def fetch_managed_state(self) -> ManagedState:
        return self.state

    def apply_managed_state(self, target_state: ManagedState) -> None:
        self.state = target_state

    def set_ruleset_deployment(
        self,
        ruleset_id: str,
        deployment_type: str,
        enabled: bool,
        alerting: bool,
        category: str | None = None,
    ) -> None:
        pass

    def create_exclusion(self, exclusion: ManagedExclusion) -> str:
        return exclusion.id

    def update_exclusion(self, exclusion: ManagedExclusion) -> None:
        pass

    def delete_exclusion(self, exclusion_id: str) -> None:
        pass


class MockReplayHarness:
    def run_test_vector(self, rule: RuleEnvelope, vector: TestVector) -> ReplayResult:
        return ReplayResult(test_id=vector.id, passed=True)

    def is_available(self) -> bool:
        return True


def test_compiler_port_conformance() -> None:
    compiler: RuleCompilerPort = MockCompiler()
    res = compiler.verify_syntax("rule valid {}")
    assert res.success is True
    res_err = compiler.verify_syntax("syntax_error")
    assert res_err.success is False


def test_deployer_port_conformance() -> None:
    deployer: RuleDeployerPort = MockDeployer()
    meta = RuleMetadata(
        id="c4e9b8f2-89b1-4f81-9b16-928d54128f73",
        name="test_rule",
        description="Desc",
    )
    envelope = RuleEnvelope(
        metadata=meta,
        logic="rule logic",
        deployment=BaseDeploymentConfig(),
        runbook=Runbook(),
        tests=(),
    )
    rule_id = deployer.create_rule(envelope)
    assert rule_id == "c4e9b8f2-89b1-4f81-9b16-928d54128f73"
    assert len(deployer.list_rules()) == 1


def test_managed_engine_port_conformance() -> None:
    engine: ManagedEnginePort = MockManagedEngine()
    state = engine.fetch_managed_state()
    assert len(state.rulesets) == 1
    assert state.rulesets[0].id == "rs-1"


def test_replay_harness_port_conformance() -> None:
    harness: ReplayHarnessPort = MockReplayHarness()
    assert harness.is_available() is True
    meta = RuleMetadata(
        id="c4e9b8f2-89b1-4f81-9b16-928d54128f73",
        name="test_rule",
        description="Desc",
    )
    envelope = RuleEnvelope(
        metadata=meta,
        logic="rule logic",
        deployment=BaseDeploymentConfig(),
        runbook=Runbook(),
        tests=(),
    )
    vec = TestVector(id="test_1", events=())
    res = harness.run_test_vector(envelope, vec)
    assert res.passed is True
    assert res.test_id == "test_1"


def test_engine_adapter_default_rule_logic_and_dataset_validation() -> None:
    from graft.core.ports.engine import EngineAdapter

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

    adapter = DummyAdapter()
    assert (
        adapter.get_default_rule_logic("login_spike")
        == 'events | where rule_name == "login_spike" and event_type == "USER_LOGIN"'
    )
    meta = RuleMetadata(
        id="c4e9b8f2-89b1-4f81-9b16-928d54128f73",
        name="login_spike",
        description="Desc",
    )
    envelope = RuleEnvelope(
        metadata=meta,
        logic="events | where src_ip in known_scanner_ips",
        deployment=BaseDeploymentConfig(),
        runbook=Runbook(),
        tests=(),
    )
    adapter.validate_rule_dataset_references(envelope, {"known_scanner_ips"})
