import dataclasses
import logging

import pytest

from graft.core.models.managed import (
    ManagedDeployment,
    ManagedExclusion,
    ManagedRuleSet,
    ManagedState,
)
from graft.core.models.rule import BaseDeploymentConfig, RuleEnvelope, RuleMetadata, Runbook
from graft.core.ports.managed import ManagedEnginePort
from graft.core.reconciler import (
    CustomRuleReconciler,
    CustomRulesReconciliationDiff,
    DeploymentDiff,
    ExclusionDiff,
    GitOpsReconciler,
    ReconciliationDiff,
)


class RecordingMockManagedEngine(ManagedEnginePort):
    def __init__(self, initial_state: ManagedState) -> None:
        self.state = initial_state
        self.deployment_calls: list[tuple[str, str, bool, bool, str | None]] = []
        self.created_exclusions: list[ManagedExclusion] = []
        self.updated_exclusions: list[ManagedExclusion] = []
        self.deleted_exclusion_ids: list[str] = []

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
        self.deployment_calls.append((ruleset_id, deployment_type, enabled, alerting, category))

    def create_exclusion(self, exclusion: ManagedExclusion) -> str:
        self.created_exclusions.append(exclusion)
        return exclusion.id

    def update_exclusion(self, exclusion: ManagedExclusion) -> None:
        self.updated_exclusions.append(exclusion)

    def delete_exclusion(self, exclusion_id: str) -> None:
        self.deleted_exclusion_ids.append(exclusion_id)


def test_diff_no_changes() -> None:
    ruleset = ManagedRuleSet(
        id="rs-cloud-threats",
        name="Cloud Threat Detections",
        category="CLOUD",
        deployments=(
            ManagedDeployment(type="PRECISE", enabled=True, alerting=True),
            ManagedDeployment(type="BROAD", enabled=False, alerting=False),
        ),
    )
    exclusion = ManagedExclusion(
        id="ex-1",
        rule_id="ru-1",
        ruleset_id="rs-cloud-threats",
        expression='$e.principal.user.userid != "svc_backup"',
        description="Backup exclusion",
    )
    state = ManagedState(rulesets=(ruleset,), exclusions=(exclusion,))

    reconciler = GitOpsReconciler()
    diff = reconciler.diff(current=state, desired=state)

    assert diff.has_changes is False
    assert len(diff.deployment_diffs) == 0
    assert len(diff.exclusions_to_create) == 0
    assert len(diff.exclusions_to_update) == 0
    assert len(diff.exclusions_to_delete) == 0
    assert len(diff.untracked_rulesets) == 0
    assert len(diff.retired_rulesets) == 0


def test_diff_deployment_toggle() -> None:
    current_rs = ManagedRuleSet(
        id="rs-cloud-threats",
        name="Cloud Threat Detections",
        category="CLOUD",
        deployments=(
            ManagedDeployment(type="PRECISE", enabled=True, alerting=False),
            ManagedDeployment(type="BROAD", enabled=False, alerting=False),
        ),
    )
    desired_rs = ManagedRuleSet(
        id="rs-cloud-threats",
        name="Cloud Threat Detections",
        category="CLOUD",
        deployments=(
            ManagedDeployment(type="PRECISE", enabled=True, alerting=True),  # alerting changed
            ManagedDeployment(type="BROAD", enabled=False, alerting=False),
        ),
    )
    current = ManagedState(rulesets=(current_rs,))
    desired = ManagedState(rulesets=(desired_rs,))

    reconciler = GitOpsReconciler()
    diff = reconciler.diff(current=current, desired=desired)

    assert diff.has_changes is True
    assert len(diff.deployment_diffs) == 1
    d_diff = diff.deployment_diffs[0]
    assert d_diff.ruleset_id == "rs-cloud-threats"
    assert d_diff.deployment_type == "PRECISE"
    assert d_diff.current_alerting is False
    assert d_diff.desired_alerting is True
    assert d_diff.has_changes is True


def test_diff_exclusions_lifecycle() -> None:
    ex_existing = ManagedExclusion(
        id="ex-existing",
        rule_id=None,
        ruleset_id="rs-1",
        expression='$e.principal.user.userid != "svc1"',
        description="Desc 1",
    )
    ex_to_update_curr = ManagedExclusion(
        id="ex-update",
        rule_id=None,
        ruleset_id="rs-1",
        expression='$e.principal.user.userid != "svc2"',
        description="Old desc",
    )
    ex_to_update_des = ManagedExclusion(
        id="ex-update",
        rule_id=None,
        ruleset_id="rs-1",
        expression='$e.principal.user.userid != "svc2_new"',
        description="New desc",
    )
    ex_to_delete = ManagedExclusion(
        id="ex-delete",
        rule_id="ru-1",
        ruleset_id="rs-1",
        expression='$e.principal.user.userid != "svc3"',
    )
    ex_to_create = ManagedExclusion(
        id="ex-create",
        rule_id=None,
        ruleset_id="rs-2",
        expression='$e.principal.user.userid != "svc4"',
        description="New exclusion",
    )

    current = ManagedState(
        rulesets=(),
        exclusions=(ex_existing, ex_to_update_curr, ex_to_delete),
    )
    desired = ManagedState(
        rulesets=(),
        exclusions=(ex_existing, ex_to_update_des, ex_to_create),
    )

    reconciler = GitOpsReconciler()
    diff = reconciler.diff(current=current, desired=desired)

    assert diff.has_changes is True
    assert len(diff.exclusions_to_create) == 1
    assert diff.exclusions_to_create[0].id == "ex-create"

    assert len(diff.exclusions_to_delete) == 1
    assert diff.exclusions_to_delete[0].id == "ex-delete"

    assert len(diff.exclusions_to_update) == 1
    u_diff = diff.exclusions_to_update[0]
    assert u_diff.id == "ex-update"
    assert u_diff.current_expression == '$e.principal.user.userid != "svc2"'
    assert u_diff.desired_expression == '$e.principal.user.userid != "svc2_new"'
    assert u_diff.has_changes is True


def test_diff_exclusions_match_by_description_when_id_differs() -> None:
    ex_tenant = ManagedExclusion(
        id="fr_1234",
        rule_id=None,
        ruleset_id="rs-1",
        expression='$e.principal.user.userid != "svc1"',
        description="Exclude service account",
    )
    ex_git = ManagedExclusion(
        id="my_exclusion",
        rule_id=None,
        ruleset_id="rs-1",
        expression='$e.principal.user.userid != "svc1"',
        description="Exclude service account",
    )

    current = ManagedState(rulesets=(), exclusions=(ex_tenant,))
    desired = ManagedState(rulesets=(), exclusions=(ex_git,))

    reconciler = GitOpsReconciler()
    diff = reconciler.diff(current=current, desired=desired)

    assert diff.has_changes is False
    assert len(diff.exclusions_to_create) == 0
    assert len(diff.exclusions_to_delete) == 0
    assert len(diff.exclusions_to_update) == 0


def test_diff_exclusions_update_matches_by_description_uses_tenant_id() -> None:
    ex_tenant = ManagedExclusion(
        id="fr_1234",
        rule_id=None,
        ruleset_id="rs-1",
        expression='$e.principal.user.userid != "svc1"',
        description="Exclude service account",
    )
    ex_git = ManagedExclusion(
        id="my_exclusion",
        rule_id=None,
        ruleset_id="rs-1",
        expression='$e.principal.user.userid != "svc1_updated"',
        description="Exclude service account",
    )

    current = ManagedState(rulesets=(), exclusions=(ex_tenant,))
    desired = ManagedState(rulesets=(), exclusions=(ex_git,))

    reconciler = GitOpsReconciler()
    diff = reconciler.diff(current=current, desired=desired)

    assert diff.has_changes is True
    assert len(diff.exclusions_to_update) == 1
    u_diff = diff.exclusions_to_update[0]
    assert u_diff.id == "fr_1234"
    assert u_diff.desired_expression == '$e.principal.user.userid != "svc1_updated"'

    engine = RecordingMockManagedEngine(initial_state=current)
    reconciler.apply(desired=desired, port=engine)
    assert len(engine.updated_exclusions) == 1
    assert engine.updated_exclusions[0].id == "fr_1234"
    assert engine.updated_exclusions[0].expression == '$e.principal.user.userid != "svc1_updated"'


def test_diff_untracked_and_retired_rulesets() -> None:
    rs_live_only = ManagedRuleSet(
        id="rs-live",
        name="Live Only",
        category="CLOUD",
        deployments=(),
    )
    rs_repo_only = ManagedRuleSet(
        id="rs-retired",
        name="Retired Upstream",
        category="ENDPOINT",
        deployments=(),
    )

    current = ManagedState(rulesets=(rs_live_only,))
    desired = ManagedState(rulesets=(rs_repo_only,))

    reconciler = GitOpsReconciler()
    diff = reconciler.diff(current=current, desired=desired)

    assert diff.has_changes is True
    assert len(diff.untracked_rulesets) == 1
    assert diff.untracked_rulesets[0].id == "rs-live"
    assert len(diff.retired_rulesets) == 1
    assert diff.retired_rulesets[0].id == "rs-retired"


def test_apply_orchestration_and_audit_logging(caplog: pytest.LogCaptureFixture) -> None:
    current_rs = ManagedRuleSet(
        id="rs-cloud-threats",
        name="Cloud Threat Detections",
        category="CLOUD",
        deployments=(ManagedDeployment(type="PRECISE", enabled=False, alerting=False),),
    )
    desired_rs = ManagedRuleSet(
        id="rs-cloud-threats",
        name="Cloud Threat Detections",
        category="CLOUD",
        deployments=(ManagedDeployment(type="PRECISE", enabled=True, alerting=True),),
    )
    ex_delete = ManagedExclusion(id="ex-old", rule_id=None, ruleset_id=None, expression="true")
    ex_create = ManagedExclusion(id="ex-new", rule_id=None, ruleset_id=None, expression="false")

    current = ManagedState(rulesets=(current_rs,), exclusions=(ex_delete,))
    desired = ManagedState(rulesets=(desired_rs,), exclusions=(ex_create,))

    engine = RecordingMockManagedEngine(initial_state=current)
    reconciler = GitOpsReconciler()

    with caplog.at_level(logging.INFO, logger="graft.reconciler"):
        diff = reconciler.apply(desired=desired, port=engine)

    assert diff.has_changes is True
    assert len(engine.deployment_calls) == 1
    assert engine.deployment_calls[0] == ("rs-cloud-threats", "PRECISE", True, True, "CLOUD")
    assert len(engine.deleted_exclusion_ids) == 1
    assert engine.deleted_exclusion_ids[0] == "ex-old"
    assert len(engine.created_exclusions) == 1
    assert engine.created_exclusions[0].id == "ex-new"

    # Verify audit logs captured the actions
    log_messages = [rec.message for rec in caplog.records]
    assert any("Applying managed deployment change" in msg for msg in log_messages)
    assert any("Deleted exclusion 'ex-old'" in msg for msg in log_messages)
    assert any("Created exclusion 'ex-new'" in msg for msg in log_messages)


def test_apply_passes_category_id_when_available() -> None:
    current_rs = ManagedRuleSet(
        id="rs-1",
        name="Test RS",
        category="Linux Threats",
        category_id="cat-uuid-1",
        deployments=(ManagedDeployment(type="PRECISE", enabled=False, alerting=False),),
    )
    desired_rs = ManagedRuleSet(
        id="rs-1",
        name="Test RS",
        category="Linux Threats",
        category_id="cat-uuid-1",
        deployments=(ManagedDeployment(type="PRECISE", enabled=True, alerting=True),),
    )
    current = ManagedState(rulesets=(current_rs,))
    desired = ManagedState(rulesets=(desired_rs,))

    engine = RecordingMockManagedEngine(initial_state=current)
    reconciler = GitOpsReconciler()
    diff = reconciler.apply(desired=desired, port=engine)

    assert diff.has_changes is True
    assert len(diff.deployment_diffs) == 1
    assert diff.deployment_diffs[0].category_id == "cat-uuid-1"
    assert engine.deployment_calls[0] == ("rs-1", "PRECISE", True, True, "cat-uuid-1")


def test_pull_mirrors_live_tenant_state(caplog: pytest.LogCaptureFixture) -> None:
    live_rs = ManagedRuleSet(
        id="rs-new-upstream",
        name="New Upstream Ruleset",
        category="CLOUD",
        deployments=(ManagedDeployment(type="PRECISE", enabled=True, alerting=True),),
    )
    live_state = ManagedState(rulesets=(live_rs,), exclusions=())
    engine = RecordingMockManagedEngine(initial_state=live_state)

    reconciler = GitOpsReconciler()
    with caplog.at_level(logging.INFO, logger="graft.reconciler"):
        pulled = reconciler.pull(port=engine)

    assert pulled == live_state
    log_messages = [rec.message for rec in caplog.records]
    assert any("Pulled managed state from tenant" in msg for msg in log_messages)


def test_render_summary() -> None:
    diff = ReconciliationDiff(
        deployment_diffs=(
            DeploymentDiff(
                ruleset_id="rs-1",
                ruleset_name="RuleSet 1",
                category="CLOUD",
                deployment_type="PRECISE",
                current_enabled=False,
                desired_enabled=True,
                current_alerting=False,
                desired_alerting=True,
            ),
        ),
        exclusions_to_create=(
            ManagedExclusion(id="ex-new", rule_id=None, ruleset_id=None, expression="e"),
        ),
        exclusions_to_update=(
            ExclusionDiff(
                id="ex-up",
                current_expression="old_e",
                desired_expression="new_e",
                current_description="",
                desired_description="updated",
                current_rule_id=None,
                desired_rule_id=None,
                current_ruleset_id=None,
                desired_ruleset_id=None,
            ),
        ),
        exclusions_to_delete=(
            ManagedExclusion(id="ex-del", rule_id=None, ruleset_id=None, expression="del"),
        ),
        untracked_rulesets=(
            ManagedRuleSet(id="rs-live", name="Live RS", category="CAT", deployments=()),
        ),
        retired_rulesets=(
            ManagedRuleSet(id="rs-ret", name="Retired RS", category="CAT", deployments=()),
        ),
    )
    summary = diff.render_summary()
    assert "[~] Deployment: rs-1 (PRECISE)" in summary
    assert "[+] Exclusion to create: ex-new" in summary
    assert "[~] Exclusion to update: ex-up" in summary
    assert "[-] Exclusion to delete: ex-del" in summary
    assert "[?] Untracked upstream ruleset: rs-live" in summary
    assert "[!] Retired upstream ruleset in repo: rs-ret" in summary


class RecordingMockRuleDeployer:
    def __init__(self, initial_rules: tuple[RuleEnvelope, ...] = ()) -> None:
        self.rules: dict[str, RuleEnvelope] = {r.metadata.name: r for r in initial_rules}
        self.created_rules: list[RuleEnvelope] = []
        self.updated_rules: list[RuleEnvelope] = []
        self.deleted_rule_ids: list[str] = []

    def list_rules(self) -> tuple[RuleEnvelope, ...]:
        return tuple(self.rules.values())

    def create_rule(self, rule: RuleEnvelope) -> str:
        rule_id = f"ru_created_{rule.metadata.name}"
        stored = dataclasses.replace(rule, metadata=dataclasses.replace(rule.metadata, id=rule_id))
        self.rules[rule.metadata.name] = stored
        self.created_rules.append(stored)
        return rule_id

    def update_rule(self, rule: RuleEnvelope) -> None:
        self.rules[rule.metadata.name] = rule
        self.updated_rules.append(rule)

    def delete_rule(self, rule_id: str) -> None:
        self.deleted_rule_ids.append(rule_id)

    def set_rule_state(self, rule_id: str, enabled: bool, alerting: bool) -> None:
        pass


def _make_envelope(
    name: str,
    rule_id: str = "uuid-1",
    logic: str = "events:\n  $e\ncondition:\n  $e",
    enabled: bool = True,
    alerting: bool = True,
) -> RuleEnvelope:
    return RuleEnvelope(
        metadata=RuleMetadata(
            id=rule_id,
            name=name,
            description="Test rule",
            status="production",
        ),
        logic=logic,
        deployment=BaseDeploymentConfig(enabled=enabled, alerting=alerting),
        runbook=Runbook(),
    )


def test_custom_rule_diff_no_changes() -> None:
    rule = _make_envelope("login_alert")
    reconciler = CustomRuleReconciler()
    diff = reconciler.diff(current=(rule,), desired=(rule,))

    assert diff.has_changes is False
    assert len(diff.rules_to_create) == 0
    assert len(diff.rules_to_update) == 0
    assert len(diff.untracked_rules) == 0


def test_custom_rule_diff_new_rule_to_create() -> None:
    desired_rule = _make_envelope("new_rule")
    reconciler = CustomRuleReconciler()
    diff = reconciler.diff(current=(), desired=(desired_rule,))

    assert diff.has_changes is True
    assert len(diff.rules_to_create) == 1
    assert diff.rules_to_create[0].metadata.name == "new_rule"
    assert len(diff.rules_to_update) == 0


def test_custom_rule_diff_modified_logic_to_update() -> None:
    current_rule = _make_envelope("login_alert", rule_id="ru_remote_123", logic="old logic")
    desired_rule = _make_envelope("login_alert", rule_id="local_uuid", logic="new logic")

    reconciler = CustomRuleReconciler()
    diff = reconciler.diff(current=(current_rule,), desired=(desired_rule,))

    assert diff.has_changes is True
    assert len(diff.rules_to_create) == 0
    assert len(diff.rules_to_update) == 1
    # Verify the remote ID was injected
    assert diff.rules_to_update[0].metadata.id == "ru_remote_123"
    assert diff.rules_to_update[0].logic == "new logic"


def test_custom_rule_diff_modified_deployment_to_update() -> None:
    current_rule = _make_envelope("login_alert", rule_id="ru_remote_123", enabled=False)
    desired_rule = _make_envelope("login_alert", rule_id="local_uuid", enabled=True)

    reconciler = CustomRuleReconciler()
    diff = reconciler.diff(current=(current_rule,), desired=(desired_rule,))

    assert diff.has_changes is True
    assert len(diff.rules_to_update) == 1
    assert diff.rules_to_update[0].deployment.enabled is True


def test_custom_rule_diff_untracked_remote_rule() -> None:
    current_rule = _make_envelope("untracked_rule", rule_id="ru_remote_999")
    reconciler = CustomRuleReconciler()
    diff = reconciler.diff(current=(current_rule,), desired=())

    assert diff.has_changes is False
    assert len(diff.untracked_rules) == 1
    assert diff.untracked_rules[0].metadata.name == "untracked_rule"


def test_custom_rule_apply_orchestration(caplog: pytest.LogCaptureFixture) -> None:
    current_rule = _make_envelope("existing_rule", rule_id="ru_remote_old", logic="old")
    deployer = RecordingMockRuleDeployer(initial_rules=(current_rule,))

    desired_update = _make_envelope("existing_rule", rule_id="local_uuid", logic="new")
    desired_create = _make_envelope("fresh_rule", rule_id="local_fresh_uuid")

    reconciler = CustomRuleReconciler()
    with caplog.at_level(logging.INFO, logger="graft.reconciler"):
        diff = reconciler.apply(desired=(desired_update, desired_create), port=deployer)

    assert diff.has_changes is True
    assert len(diff.rules_to_create) == 1
    assert len(diff.rules_to_update) == 1
    assert len(deployer.created_rules) == 1
    assert len(deployer.updated_rules) == 1
    assert deployer.updated_rules[0].metadata.id == "ru_remote_old"

    log_messages = [rec.message for rec in caplog.records]
    assert any("Created custom rule 'fresh_rule'" in msg for msg in log_messages)
    assert any("Updated custom rule 'existing_rule'" in msg for msg in log_messages)


def test_custom_rules_render_summary() -> None:
    rule_create = _make_envelope("create_me")
    rule_update = _make_envelope("update_me", rule_id="ru_123")
    rule_untracked = _make_envelope("untracked_me", rule_id="ru_456")

    diff = CustomRulesReconciliationDiff(
        rules_to_create=(rule_create,),
        rules_to_update=(rule_update,),
        untracked_rules=(rule_untracked,),
    )
    summary = diff.render_summary()
    assert "[+] Custom rule to create: create_me" in summary
    assert "[~] Custom rule to update: update_me (ID: ru_123)" in summary
    assert "[?] Untracked custom rule on tenant: untracked_me (ID: ru_456)" in summary


def test_custom_rule_diff_scoped_ignores_untracked() -> None:
    remote_untracked = _make_envelope("untracked_rule", rule_id="ru_remote_999")
    remote_tracked = _make_envelope("login_alert", rule_id="ru_remote_123", enabled=False)
    desired_tracked = _make_envelope("login_alert", rule_id="local_uuid", enabled=True)

    reconciler = CustomRuleReconciler()

    # In default/unscoped mode (Mode A): untracked_rule is detected
    diff_unscoped = reconciler.diff(
        current=(remote_untracked, remote_tracked),
        desired=(desired_tracked,),
        scoped=False,
    )
    assert len(diff_unscoped.untracked_rules) == 1
    assert diff_unscoped.untracked_rules[0].metadata.name == "untracked_rule"
    assert len(diff_unscoped.rules_to_update) == 1

    # In scoped mode (Mode B): untracked_rule is omitted from untracked_rules
    diff_scoped = reconciler.diff(
        current=(remote_untracked, remote_tracked),
        desired=(desired_tracked,),
        scoped=True,
    )
    assert len(diff_scoped.untracked_rules) == 0
    assert len(diff_scoped.rules_to_update) == 1
    assert diff_scoped.rules_to_update[0].metadata.name == "login_alert"
