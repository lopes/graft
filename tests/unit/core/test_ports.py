from graft.core.models.compiler import CompilationResult
from graft.core.models.managed import ManagedDeployment, ManagedRuleSet, ManagedState
from graft.core.models.rule import (
    BaseDeploymentConfig,
    InvestigationGuide,
    RuleEnvelope,
    RuleMetadata,
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
        self, ruleset_id: str, deployment_type: str, enabled: bool, alerting: bool
    ) -> None:
        pass


class MockReplayHarness:
    def run_test_vector(self, rule: RuleEnvelope, vector: TestVector) -> ReplayResult:
        return ReplayResult(vector_name=vector.name, passed=True)

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
        id="RULE-100",
        name="Test Rule",
        description="Desc",
        severity="LOW",
        authors=(),
        mitre_attack={},
        tags=(),
        references=(),
    )
    envelope = RuleEnvelope(
        metadata=meta,
        logic="rule logic",
        deployment=BaseDeploymentConfig(),
        guide=InvestigationGuide(
            context="", triage_runbook="", false_positives=(), response_playbooks=()
        ),
        test=(),
    )
    rule_id = deployer.create_rule(envelope)
    assert rule_id == "RULE-100"
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
        id="RULE-100",
        name="Test Rule",
        description="Desc",
        severity="LOW",
        authors=(),
        mitre_attack={},
        tags=(),
        references=(),
    )
    envelope = RuleEnvelope(
        metadata=meta,
        logic="rule logic",
        deployment=BaseDeploymentConfig(),
        guide=InvestigationGuide(
            context="", triage_runbook="", false_positives=(), response_playbooks=()
        ),
        test=(),
    )
    vec = TestVector(name="Test 1", events=())
    res = harness.run_test_vector(envelope, vec)
    assert res.passed is True
