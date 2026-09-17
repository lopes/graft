import logging
from dataclasses import dataclass

from graft.core.models.managed import (
    ManagedExclusion,
    ManagedRuleSet,
    ManagedState,
)
from graft.core.ports.managed import ManagedEnginePort

logger = logging.getLogger("graft.reconciler")


@dataclass(frozen=True)
class DeploymentDiff:
    ruleset_id: str
    ruleset_name: str
    category: str
    deployment_type: str
    current_enabled: bool
    desired_enabled: bool
    current_alerting: bool
    desired_alerting: bool

    @property
    def has_changes(self) -> bool:
        return (self.current_enabled != self.desired_enabled) or (
            self.current_alerting != self.desired_alerting
        )


@dataclass(frozen=True)
class ExclusionDiff:
    id: str
    current_expression: str
    desired_expression: str
    current_description: str
    desired_description: str
    current_rule_id: str | None
    desired_rule_id: str | None
    current_ruleset_id: str | None
    desired_ruleset_id: str | None

    @property
    def has_changes(self) -> bool:
        return (
            self.current_expression != self.desired_expression
            or self.current_description != self.desired_description
            or self.current_rule_id != self.desired_rule_id
            or self.current_ruleset_id != self.desired_ruleset_id
        )


@dataclass(frozen=True)
class ReconciliationDiff:
    deployment_diffs: tuple[DeploymentDiff, ...] = ()
    exclusions_to_create: tuple[ManagedExclusion, ...] = ()
    exclusions_to_update: tuple[ExclusionDiff, ...] = ()
    exclusions_to_delete: tuple[ManagedExclusion, ...] = ()
    untracked_rulesets: tuple[ManagedRuleSet, ...] = ()
    retired_rulesets: tuple[ManagedRuleSet, ...] = ()

    @property
    def has_changes(self) -> bool:
        return (
            any(d.has_changes for d in self.deployment_diffs)
            or bool(self.exclusions_to_create)
            or any(e.has_changes for e in self.exclusions_to_update)
            or bool(self.exclusions_to_delete)
            or bool(self.untracked_rulesets)
            or bool(self.retired_rulesets)
        )

    def render_summary(self) -> str:
        lines: list[str] = []
        if not self.has_changes:
            return "No changes detected. Git repository is synchronized with tenant."

        for dep in self.deployment_diffs:
            if dep.has_changes:
                lines.append(
                    f"[~] Deployment: {dep.ruleset_id} ({dep.deployment_type}) | "
                    f"enabled: {dep.current_enabled} -> {dep.desired_enabled}, "
                    f"alerting: {dep.current_alerting} -> {dep.desired_alerting}"
                )

        for excl in self.exclusions_to_create:
            lines.append(f"[+] Exclusion to create: {excl.id}")

        for excl_diff in self.exclusions_to_update:
            if excl_diff.has_changes:
                lines.append(f"[~] Exclusion to update: {excl_diff.id}")

        for excl in self.exclusions_to_delete:
            lines.append(f"[-] Exclusion to delete: {excl.id}")

        for untracked in self.untracked_rulesets:
            lines.append(f"[?] Untracked upstream ruleset: {untracked.id} ({untracked.name})")

        for retired in self.retired_rulesets:
            lines.append(f"[!] Retired upstream ruleset in repo: {retired.id} ({retired.name})")

        return "\n".join(lines)


class GitOpsReconciler:
    def diff(self, current: ManagedState, desired: ManagedState) -> ReconciliationDiff:
        current_rs_map = {rs.id: rs for rs in current.rulesets}
        desired_rs_map = {rs.id: rs for rs in desired.rulesets}

        untracked: list[ManagedRuleSet] = [
            rs for rs_id, rs in current_rs_map.items() if rs_id not in desired_rs_map
        ]
        retired: list[ManagedRuleSet] = [
            rs for rs_id, rs in desired_rs_map.items() if rs_id not in current_rs_map
        ]

        deployment_diffs: list[DeploymentDiff] = []
        for rs_id, desired_rs in desired_rs_map.items():
            if rs_id not in current_rs_map:
                continue
            curr_rs = current_rs_map[rs_id]
            curr_deps = {d.type: d for d in curr_rs.deployments}
            for des_dep in desired_rs.deployments:
                curr_dep = curr_deps.get(des_dep.type)
                curr_enabled = curr_dep.enabled if curr_dep else False
                curr_alerting = curr_dep.alerting if curr_dep else False
                diff_entry = DeploymentDiff(
                    ruleset_id=rs_id,
                    ruleset_name=desired_rs.name,
                    category=desired_rs.category,
                    deployment_type=des_dep.type,
                    current_enabled=curr_enabled,
                    desired_enabled=des_dep.enabled,
                    current_alerting=curr_alerting,
                    desired_alerting=des_dep.alerting,
                )
                if diff_entry.has_changes:
                    deployment_diffs.append(diff_entry)

        curr_excl_map = {e.id: e for e in current.exclusions}
        des_excl_map = {e.id: e for e in desired.exclusions}

        exclusions_to_create: list[ManagedExclusion] = [
            e for e_id, e in des_excl_map.items() if e_id not in curr_excl_map
        ]
        exclusions_to_delete: list[ManagedExclusion] = [
            e for e_id, e in curr_excl_map.items() if e_id not in des_excl_map
        ]

        exclusions_to_update: list[ExclusionDiff] = []
        for e_id, des_excl in des_excl_map.items():
            if e_id not in curr_excl_map:
                continue
            curr_excl = curr_excl_map[e_id]
            e_diff = ExclusionDiff(
                id=e_id,
                current_expression=curr_excl.expression,
                desired_expression=des_excl.expression,
                current_description=curr_excl.description,
                desired_description=des_excl.description,
                current_rule_id=curr_excl.rule_id,
                desired_rule_id=des_excl.rule_id,
                current_ruleset_id=curr_excl.ruleset_id,
                desired_ruleset_id=des_excl.ruleset_id,
            )
            if e_diff.has_changes:
                exclusions_to_update.append(e_diff)

        return ReconciliationDiff(
            deployment_diffs=tuple(deployment_diffs),
            exclusions_to_create=tuple(exclusions_to_create),
            exclusions_to_update=tuple(exclusions_to_update),
            exclusions_to_delete=tuple(exclusions_to_delete),
            untracked_rulesets=tuple(untracked),
            retired_rulesets=tuple(retired),
        )

    def apply(self, desired: ManagedState, port: ManagedEnginePort) -> ReconciliationDiff:
        logger.info("Starting managed state reconciliation against target tenant")
        current = port.fetch_managed_state()
        reconcile_diff = self.diff(current=current, desired=desired)

        if not reconcile_diff.has_changes:
            logger.info(
                "Target tenant is already aligned with desired managed state. No actions taken."
            )
            return reconcile_diff

        # Apply deployment toggles
        for dep in reconcile_diff.deployment_diffs:
            if dep.has_changes:
                logger.info(
                    "Applying managed deployment change: %s (%s) [enabled: %s, alerting: %s]",
                    dep.ruleset_id,
                    dep.deployment_type,
                    dep.desired_enabled,
                    dep.desired_alerting,
                )
                port.set_ruleset_deployment(
                    ruleset_id=dep.ruleset_id,
                    deployment_type=dep.deployment_type,
                    enabled=dep.desired_enabled,
                    alerting=dep.desired_alerting,
                    category=dep.category,
                )

        # Apply deletions
        for excl in reconcile_diff.exclusions_to_delete:
            logger.info("Deleted exclusion '%s' from tenant", excl.id)
            port.delete_exclusion(excl.id)

        # Apply updates
        des_excl_map = {e.id: e for e in desired.exclusions}
        for u_diff in reconcile_diff.exclusions_to_update:
            if u_diff.has_changes and u_diff.id in des_excl_map:
                logger.info("Updated exclusion '%s' in tenant", u_diff.id)
                port.update_exclusion(des_excl_map[u_diff.id])

        # Apply creations
        for excl in reconcile_diff.exclusions_to_create:
            logger.info("Created exclusion '%s' in tenant", excl.id)
            port.create_exclusion(excl)

        logger.info(
            "Managed state reconciliation complete. %d actions executed.",
            len(reconcile_diff.deployment_diffs)
            + len(reconcile_diff.exclusions_to_delete)
            + len(reconcile_diff.exclusions_to_update)
            + len(reconcile_diff.exclusions_to_create),
        )
        return reconcile_diff

    def pull(self, port: ManagedEnginePort) -> ManagedState:
        logger.info("Initiating managed state pull from target tenant")
        state = port.fetch_managed_state()
        logger.info(
            "Pulled managed state from tenant: %d rulesets, %d exclusions",
            len(state.rulesets),
            len(state.exclusions),
        )
        return state
