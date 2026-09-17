import logging

import pytest

from graft.core.models.managed import (
    ManagedDeployment,
    ManagedExclusion,
    ManagedRuleSet,
    ManagedState,
)
from graft.core.ports.managed import ManagedEnginePort
from graft.core.reconciler import (
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
