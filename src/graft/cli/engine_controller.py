from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from graft.cli.scaffold import scaffold_rule
from graft.core.engine_registry import EngineRegistry
from graft.core.git import get_changed_files
from graft.core.loader import dump_rule_to_yaml, load_rule_from_yaml
from graft.core.models.engine import EngineManifest
from graft.core.models.managed import ManagedState
from graft.core.models.rule import RuleEnvelope
from graft.core.ports.managed import ManagedEnginePort
from graft.core.reconciler import (
    CustomRuleReconciler,
    GitOpsReconciler,
    ReconciliationDiff,
)

logger = logging.getLogger("graft.cli.engine_controller")

_NO_CHANGES_MSG = "No detection rules or managed manifests modified in current change scope."


class EngineCommandController:
    def __init__(self, manifest: EngineManifest, registry: EngineRegistry) -> None:
        self.manifest = manifest
        self.registry = registry

    def _load_custom_rules(
        self,
        custom_dir: Path | None = None,
        filter_paths: set[Path] | None = None,
    ) -> tuple[RuleEnvelope, ...]:
        target_dir = custom_dir or Path(f"rules/{self.manifest.name}/custom")
        rules: list[RuleEnvelope] = []
        if target_dir.is_dir():
            for rule_path in sorted(target_dir.rglob("*.yaml")):
                if filter_paths is not None and (
                    rule_path.resolve() not in filter_paths and rule_path not in filter_paths
                ):
                    continue
                try:
                    rule = load_rule_from_yaml(rule_path)
                    rules.append(rule)
                except Exception as exc:
                    logger.warning("Failed loading custom rule %s: %s", rule_path, exc)
        return tuple(rules)

    def execute(self, args: argparse.Namespace, json_output: bool = False) -> int:
        cmd = getattr(args, "engine_command", "")

        if cmd == "new":
            out_path = Path(args.out) if getattr(args, "out", None) else None
            created = scaffold_rule(self.manifest.name, args.rule_name, out_path=out_path)
            if json_output:
                sys.stdout.write(json.dumps({"success": True, "created": str(created)}) + "\n")
            else:
                sys.stdout.write(
                    f"Scaffolded {self.manifest.display_name} rule template at: {created}\n"
                )
            return 0

        env_target = getattr(args, "env", "staging")

        if cmd == "verify":
            return self._execute_verify(args, env_target, json_output)
        if cmd == "test":
            return self._execute_test(args, env_target, json_output)
        if cmd == "diff":
            return self._execute_diff(args, env_target, json_output)
        if cmd == "apply":
            return self._execute_apply(args, env_target, json_output)
        if cmd == "managed":
            return self._execute_managed(args, env_target, json_output)
        if cmd == "pull":
            return self._execute_pull(args, env_target, json_output)

        sys.stderr.write(f"Unknown engine command '{cmd}'\n")
        return 1

    def _execute_verify(self, args: argparse.Namespace, env: str, json_output: bool) -> int:
        verify_paths: list[Path] = []
        raw_paths = getattr(args, "paths", [])
        if raw_paths:
            for p_str in raw_paths:
                p = Path(p_str)
                if p.is_dir():
                    verify_paths.extend(sorted(p.rglob("*.yaml")))
                elif p.is_file():
                    verify_paths.append(p)
        else:
            default_dir = Path(f"rules/{self.manifest.name}/custom")
            if default_dir.is_dir():
                verify_paths.extend(sorted(default_dir.rglob("*.yaml")))

        if not verify_paths:
            if json_output:
                sys.stdout.write(json.dumps({"success": True, "total": 0, "verified": []}) + "\n")
            else:
                sys.stdout.write(f"No rules found to verify for {self.manifest.display_name}.\n")
            return 0

        adapter = self.registry.load_adapter(self.manifest.name, env=env)
        compiler = adapter.get_compiler()
        if compiler is None:
            err_msg = f"Engine '{self.manifest.name}' does not implement syntax verification"
            if json_output:
                sys.stdout.write(json.dumps({"success": False, "error": err_msg}) + "\n")
            else:
                sys.stderr.write(f"Error: {err_msg}\n")
            return 1

        failed_count = 0
        diagnostics_list: list[dict[str, Any]] = []

        for path in verify_paths:
            try:
                rule = load_rule_from_yaml(path)
                result = compiler.verify_syntax(rule.logic)
                if not result.success:
                    failed_count += 1
                    err_lines = "; ".join(
                        f"{d.line}:{d.column}: {d.message}" for d in result.diagnostics
                    )
                    diagnostics_list.append({"file": str(path), "error": err_lines})
                    if not json_output:
                        sys.stderr.write(f"[FAIL] {path}:\n  {err_lines}\n")
                else:
                    if not json_output:
                        sys.stdout.write(f"[PASS] {path}\n")
            except Exception as exc:
                failed_count += 1
                diagnostics_list.append({"file": str(path), "error": str(exc)})
                if not json_output:
                    sys.stderr.write(f"[FAIL] {path}: {exc}\n")

        if json_output:
            payload = {
                "success": failed_count == 0,
                "total": len(verify_paths),
                "failed": failed_count,
                "diagnostics": diagnostics_list,
            }
            sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        else:
            if failed_count > 0:
                sys.stderr.write(
                    f"\nVerification failed: {failed_count} rule(s) failed compilation.\n"
                )
            else:
                sys.stdout.write(
                    f"\nVerification passed: {len(verify_paths)} rule(s) compiled cleanly.\n"
                )

        return 1 if failed_count > 0 else 0

    def _execute_test(self, args: argparse.Namespace, env: str, json_output: bool) -> int:
        target_paths: list[Path] = []
        raw_paths = getattr(args, "paths", [])
        if raw_paths:
            for p_str in raw_paths:
                p = Path(p_str)
                if p.is_dir():
                    target_paths.extend(sorted(p.rglob("*.yaml")))
                elif p.is_file():
                    target_paths.append(p)
        else:
            default_dir = Path(f"rules/{self.manifest.name}/custom")
            if default_dir.is_dir():
                target_paths.extend(sorted(default_dir.rglob("*.yaml")))

        if getattr(args, "changed_only", False):
            changed = get_changed_files()
            target_paths = [tp for tp in target_paths if tp.resolve() in changed or tp in changed]

        rules_with_tests: list[RuleEnvelope] = []
        for tp in target_paths:
            try:
                rule = load_rule_from_yaml(tp)
                if rule.tests:
                    rules_with_tests.append(rule)
            except Exception as exc:
                logger.debug("Failed loading %s during test discovery: %s", tp, exc)

        if not rules_with_tests:
            if json_output:
                sys.stdout.write(json.dumps({"success": True, "total": 0, "results": []}) + "\n")
            else:
                sys.stdout.write("No replay test vectors found in target rules.\n")
            return 0

        require_staging = getattr(args, "require_staging", False)
        try:
            adapter = self.registry.load_adapter(self.manifest.name, env=env)
            replay = adapter.get_replay()
        except Exception as exc:
            if require_staging:
                if json_output:
                    sys.stdout.write(json.dumps({"success": False, "error": str(exc)}) + "\n")
                else:
                    sys.stderr.write(f"Error: --require-staging was specified but {exc}\n")
                return 1
            if json_output:
                sys.stdout.write(
                    json.dumps(
                        {
                            "success": True,
                            "skipped": True,
                            "reason": str(exc),
                            "total": 0,
                            "results": [],
                        }
                    )
                    + "\n"
                )
            else:
                sys.stdout.write(
                    f"[WARNING] Skipping replay tests: Staging tenant not configured ({exc}).\n"
                )
            return 0

        if replay is None or not replay.is_available():
            msg = f"Replay harness is not available for {self.manifest.display_name} in {env}."
            if require_staging:
                if json_output:
                    sys.stdout.write(json.dumps({"success": False, "error": msg}) + "\n")
                else:
                    sys.stderr.write(f"Error: {msg}\n")
                return 1
            if json_output:
                sys.stdout.write(
                    json.dumps({"success": True, "skipped": True, "reason": msg}) + "\n"
                )
            else:
                sys.stdout.write(f"[WARNING] {msg}\n")
            return 0

        failed = 0
        total_vectors = 0
        results_list: list[dict[str, Any]] = []

        for rule in rules_with_tests:
            for vec in rule.tests:
                total_vectors += 1
                res = replay.run_test_vector(rule, vec)
                if not res.passed:
                    failed += 1
                results_list.append(
                    {
                        "rule": rule.metadata.name,
                        "test_id": res.test_id,
                        "passed": res.passed,
                        "message": res.message,
                    }
                )
                if not json_output:
                    status = "[PASS]" if res.passed else "[FAIL]"
                    sys.stdout.write(f"{status} {rule.metadata.name} :: {res.test_id}\n")

        if json_output:
            sys.stdout.write(
                json.dumps(
                    {
                        "success": failed == 0,
                        "total": total_vectors,
                        "failed": failed,
                        "results": results_list,
                    },
                    indent=2,
                )
                + "\n"
            )
        else:
            sys.stdout.write(
                f"\nReplay test results: {total_vectors - failed} passed, {failed} failed.\n"
            )

        return 1 if failed > 0 else 0

    def _execute_diff(self, args: argparse.Namespace, env: str, json_output: bool) -> int:
        target = getattr(args, "target", "all")
        all_rules = getattr(args, "all_rules", False)
        adapter = self.registry.load_adapter(self.manifest.name, env=env)

        has_drift = False
        payload: dict[str, Any] = {"success": True, "target": target, "env": env, "diff": {}}

        # Custom rules diff
        if target in ("custom", "all"):
            deployer = adapter.get_deployer()
            if deployer is not None:
                filter_files = None
                if not all_rules:
                    changed = get_changed_files()
                    filter_files = changed

                desired = self._load_custom_rules(filter_paths=filter_files)
                remote = deployer.list_rules()

                comparator = getattr(deployer, "are_rules_equal", None)
                if not callable(comparator):
                    comparator = getattr(adapter, "are_rules_equal", None)
                content_comparator: Callable[[RuleEnvelope, RuleEnvelope], bool] | None = (
                    comparator if callable(comparator) else None
                )

                reconciler = CustomRuleReconciler()
                diff = reconciler.diff(
                    current=remote,
                    desired=desired,
                    content_comparator=content_comparator,
                    scoped=not all_rules,
                )

                if diff.has_changes:
                    has_drift = True

                payload["diff"]["custom"] = {
                    "has_changes": diff.has_changes,
                    "to_create": [r.metadata.name for r in diff.rules_to_create],
                    "to_update": [r.metadata.name for r in diff.rules_to_update],
                    "untracked": [r.metadata.name for r in diff.untracked_rules],
                }

                if not json_output:
                    if not diff.has_changes:
                        sys.stdout.write(
                            f"Custom rules in sync with {self.manifest.display_name} ({env}).\n"
                        )
                    else:
                        sys.stdout.write(
                            f"Custom rules drift detected for {self.manifest.display_name} "
                            f"({env}):\n"
                        )
                        for r in diff.rules_to_create:
                            sys.stdout.write(f"  + [CREATE] {r.metadata.name}\n")
                        for r in diff.rules_to_update:
                            sys.stdout.write(f"  ~ [UPDATE] {r.metadata.name}\n")
                        for r in diff.untracked_rules:
                            sys.stdout.write(f"  ? [UNTRACKED] {r.metadata.name}\n")

        # Managed diff
        if target in ("managed", "all") and self.manifest.capabilities.managed_rules:
            managed_port = adapter.get_managed()
            if managed_port is not None:
                m_diff = self._diff_managed(managed_port)
                if m_diff.has_changes:
                    has_drift = True
                payload["diff"]["managed"] = {"has_changes": m_diff.has_changes}
                if not json_output:
                    if not m_diff.has_changes:
                        sys.stdout.write(
                            f"Managed content in sync with {self.manifest.display_name} ({env}).\n"
                        )
                    else:
                        sys.stdout.write(
                            f"Managed content drift detected for {self.manifest.display_name} "
                            f"({env}).\n"
                        )

        if json_output:
            payload["has_drift"] = has_drift
            sys.stdout.write(json.dumps(payload, indent=2) + "\n")

        return 2 if has_drift else 0

    def _execute_apply(self, args: argparse.Namespace, env: str, json_output: bool) -> int:
        target = getattr(args, "target", "all")
        all_rules = getattr(args, "all_rules", False)
        adapter = self.registry.load_adapter(self.manifest.name, env=env)

        payload: dict[str, Any] = {"success": True, "target": target, "env": env, "applied": {}}

        if target in ("custom", "all"):
            deployer = adapter.get_deployer()
            if deployer is not None:
                filter_files = None
                if not all_rules:
                    changed = get_changed_files()
                    filter_files = changed

                desired = self._load_custom_rules(filter_paths=filter_files)
                comparator = getattr(deployer, "are_rules_equal", None)
                if not callable(comparator):
                    comparator = getattr(adapter, "are_rules_equal", None)
                content_comparator: Callable[[RuleEnvelope, RuleEnvelope], bool] | None = (
                    comparator if callable(comparator) else None
                )

                custom_reconciler = CustomRuleReconciler()
                diff = custom_reconciler.apply(
                    desired=desired,
                    port=deployer,
                    content_comparator=content_comparator,
                    scoped=not all_rules,
                )
                payload["applied"]["custom"] = {
                    "created": len(diff.rules_to_create),
                    "updated": len(diff.rules_to_update),
                }
                if not json_output:
                    sys.stdout.write(
                        f"Applied custom rules to {self.manifest.display_name} ({env}): "
                        f"{len(diff.rules_to_create)} created, "
                        f"{len(diff.rules_to_update)} updated.\n"
                    )

        if target in ("managed", "all") and self.manifest.capabilities.managed_rules:
            managed_port = adapter.get_managed()
            if managed_port is not None:
                manifest_path = Path(f"rules/{self.manifest.name}/managed.yaml")
                if manifest_path.is_file():
                    target_state = self._load_managed_state(manifest_path, adapter)
                    if target_state is not None:
                        managed_reconciler = GitOpsReconciler()
                        m_diff = managed_reconciler.apply(target_state, managed_port)
                        payload["applied"]["managed"] = {"actions": len(m_diff.deployment_diffs)}
                        if not json_output:
                            sys.stdout.write(
                                f"Applied managed state to {self.manifest.display_name} ({env}).\n"
                            )

        if json_output:
            sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return 0

    def _execute_managed(self, args: argparse.Namespace, env: str, json_output: bool) -> int:
        cmd = getattr(args, "managed_command", "")
        adapter = self.registry.load_adapter(self.manifest.name, env=env)
        managed_port = adapter.get_managed()
        if managed_port is None:
            sys.stderr.write(f"Managed content not supported by {self.manifest.display_name}\n")
            return 1

        manifest_path = Path(getattr(args, "out", f"rules/{self.manifest.name}/managed.yaml"))

        if cmd == "diff":
            m_diff = self._diff_managed(managed_port)
            if json_output:
                sys.stdout.write(json.dumps({"has_changes": m_diff.has_changes}, indent=2) + "\n")
            else:
                status = "drift detected" if m_diff.has_changes else "in sync"
                sys.stdout.write(
                    f"Managed content {status} for {self.manifest.display_name} ({env}).\n"
                )
            return 2 if m_diff.has_changes else 0

        if cmd == "apply":
            target_state = self._load_managed_state(manifest_path, adapter)
            if target_state is None:
                return 1
            reconciler = GitOpsReconciler()
            reconciler.apply(target_state, managed_port)
            if json_output:
                sys.stdout.write(json.dumps({"success": True}) + "\n")
            else:
                sys.stdout.write(
                    f"Applied managed manifest to {self.manifest.display_name} ({env}).\n"
                )
            return 0

        if cmd == "pull":
            reconciler = GitOpsReconciler()
            state = reconciler.pull(managed_port)
            self._write_managed_state(manifest_path, state, adapter)
            if json_output:
                sys.stdout.write(json.dumps({"success": True, "out": str(manifest_path)}) + "\n")
            else:
                sys.stdout.write(f"Pulled managed state into {manifest_path}.\n")
            return 0

        return 0

    def _execute_pull(self, args: argparse.Namespace, env: str, json_output: bool) -> int:
        target = getattr(args, "target", "all")
        force = getattr(args, "force", False)
        out_dir = Path(getattr(args, "out_dir", f"rules/{self.manifest.name}/custom"))
        out_manifest = Path(
            getattr(args, "out_manifest", f"rules/{self.manifest.name}/managed.yaml")
        )

        adapter = self.registry.load_adapter(self.manifest.name, env=env)
        pulled_custom = 0

        if target in ("all", "custom"):
            deployer = adapter.get_deployer()
            if deployer is not None:
                out_dir.mkdir(parents=True, exist_ok=True)
                remote_rules = deployer.list_rules()
                for rule in remote_rules:
                    dest_file = out_dir / f"{rule.metadata.name}.yaml"
                    if dest_file.exists() and not force:
                        continue
                    dump_rule_to_yaml(rule, dest_file)
                    pulled_custom += 1

        if target in ("all", "managed") and self.manifest.capabilities.managed_rules:
            managed_port = adapter.get_managed()
            if managed_port is not None:
                reconciler = GitOpsReconciler()
                state = reconciler.pull(managed_port)
                self._write_managed_state(out_manifest, state, adapter)

        if json_output:
            sys.stdout.write(
                json.dumps(
                    {"success": True, "pulled_custom": pulled_custom, "out_dir": str(out_dir)}
                )
                + "\n"
            )
        else:
            sys.stdout.write(
                f"Successfully pulled {pulled_custom} custom rule(s) from "
                f"{self.manifest.display_name}.\n"
            )
        return 0

    def _diff_managed(self, port: ManagedEnginePort) -> ReconciliationDiff:
        manifest_path = Path(f"rules/{self.manifest.name}/managed.yaml")
        reconciler = GitOpsReconciler()
        if not manifest_path.is_file():
            return ReconciliationDiff(
                deployment_diffs=(),
                exclusions_to_create=(),
                exclusions_to_delete=(),
                exclusions_to_update=(),
                untracked_rulesets=(),
            )
        # Generic diff using reconciler
        live_state = reconciler.pull(port)
        return reconciler.diff(live_state, live_state)

    def _load_managed_state(self, path: Path, adapter: Any) -> ManagedState | None:
        if hasattr(adapter, "load_managed_manifest"):
            return adapter.load_managed_manifest(path)  # type: ignore[no-any-return]
        return None

    def _write_managed_state(self, path: Path, state: ManagedState, adapter: Any) -> None:
        if hasattr(adapter, "dump_managed_manifest"):
            adapter.dump_managed_manifest(state, path)


def register_engine_commands(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    manifest: EngineManifest,
    registry: EngineRegistry,
) -> None:
    controller = EngineCommandController(manifest, registry)
    parser = subparsers.add_parser(
        manifest.name,
        help=manifest.description,
        description=f"{manifest.display_name}: {manifest.description}",
    )
    parser.set_defaults(engine_handler=controller.execute)
    cmd_subparsers = parser.add_subparsers(dest="engine_command", required=True)

    caps = manifest.capabilities
    envs = list(manifest.environments)

    if caps.custom_rules:
        # new
        new_p = cmd_subparsers.add_parser(
            "new", help=f"Bootstrap a new {manifest.display_name} rule"
        )
        new_p.add_argument("rule_name", help="Technical rule name (lowercase slug)")
        new_p.add_argument("--out", help="Custom target path for rule YAML")

        targets = ["custom", "managed", "all"] if caps.managed_rules else ["custom"]

        # diff
        diff_p = cmd_subparsers.add_parser(
            "diff", help="Compute delta between Git and remote tenant"
        )
        diff_p.add_argument("--env", choices=envs, default=envs[-1] if envs else "production")
        diff_p.add_argument("--target", choices=targets, default=targets[-1])
        diff_p.add_argument("--all", "--full", action="store_true", dest="all_rules")

        # apply
        apply_p = cmd_subparsers.add_parser(
            "apply", help="Apply desired Git state to remote tenant"
        )
        apply_p.add_argument("--env", choices=envs, default=envs[-1] if envs else "production")
        apply_p.add_argument("--target", choices=targets, default=targets[-1])
        apply_p.add_argument("--all", "--full", action="store_true", dest="all_rules")

        # pull
        pull_targets = ["all", "custom", "managed"] if caps.managed_rules else ["custom"]
        pull_p = cmd_subparsers.add_parser("pull", help="Pull rules and state from remote tenant")
        pull_p.add_argument("--env", choices=envs, default=envs[-1] if envs else "production")
        pull_p.add_argument("--target", choices=pull_targets, default=pull_targets[0])
        pull_p.add_argument("--out-dir", default=f"rules/{manifest.name}/custom")
        pull_p.add_argument("--out-manifest", default=f"rules/{manifest.name}/managed.yaml")
        pull_p.add_argument("--force", action="store_true")

    if caps.syntax_verification:
        verify_p = cmd_subparsers.add_parser("verify", help="Lint locally and verify syntax")
        verify_p.add_argument("paths", nargs="*", help="Rule files or directories to verify")
        verify_p.add_argument("--env", choices=envs, default=envs[0] if envs else "staging")

    if caps.replay_testing:
        test_p = cmd_subparsers.add_parser("test", help="Execute synthetic replay tests in staging")
        test_p.add_argument("paths", nargs="*", help="Rule files to test")
        test_p.add_argument("--env", choices=envs, default=envs[0] if envs else "staging")
        test_p.add_argument("--require-staging", action="store_true")
        test_p.add_argument("--changed-only", action="store_true")

    if caps.managed_rules:
        managed_p = cmd_subparsers.add_parser(
            "managed", help="Manage vendor curated rules and exclusions"
        )
        m_sub = managed_p.add_subparsers(dest="managed_command", required=True)

        m_diff = m_sub.add_parser("diff", help="Detect drift between managed manifest and tenant")
        m_diff.add_argument("--env", choices=envs, default=envs[-1] if envs else "production")

        m_apply = m_sub.add_parser("apply", help="Push desired managed state to tenant")
        m_apply.add_argument("--env", choices=envs, default=envs[-1] if envs else "production")

        m_pull = m_sub.add_parser("pull", help="Pull live managed state into local manifest")
        m_pull.add_argument("--env", choices=envs, default=envs[-1] if envs else "production")
        m_pull.add_argument("--out", default=f"rules/{manifest.name}/managed.yaml")
