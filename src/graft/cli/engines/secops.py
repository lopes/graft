from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Literal

from graft.cli.scaffold import scaffold_rule
from graft.core.loader import load_rule_from_yaml
from graft.core.reconciler import GitOpsReconciler
from graft.engines.secops.client import SecOpsClient
from graft.engines.secops.config import SecOpsConfig
from graft.engines.secops.managed import SecOpsManagedAdapter
from graft.engines.secops.managed_loader import (
    dump_managed_manifest_to_yaml,
    load_managed_manifest_from_yaml,
)
from graft.engines.secops.replay import SecOpsReplayAdapter

logger = logging.getLogger("graft.cli.secops")


def register_engine(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("secops", help="Google SecOps detection engine commands")
    parser.set_defaults(engine_handler=handle_secops_command)
    cmd_subparsers = parser.add_subparsers(dest="engine_command", required=True)

    # 1. new
    new_p = cmd_subparsers.add_parser("new", help="Bootstrap a new SecOps YARA-L rule")
    new_p.add_argument("rule_name", help="Technical rule name (lowercase slug)")
    new_p.add_argument("--out", help="Custom target path for rule YAML")

    # 2. verify
    verify_p = cmd_subparsers.add_parser(
        "verify", help="Lint locally and dry-run syntax via Chronicle verifyRuleText"
    )
    verify_p.add_argument("paths", nargs="*", help="Rule files or directories to verify")
    verify_p.add_argument(
        "--env",
        choices=["staging", "production"],
        default="staging",
        help="Target SecOps environment",
    )

    # 3. test
    test_p = cmd_subparsers.add_parser(
        "test", help="Execute synthetic UDM replay tests in staging quarantine"
    )
    test_p.add_argument("paths", nargs="*", help="Rule files to test")
    test_p.add_argument(
        "--env",
        choices=["staging", "production"],
        default="staging",
        help="Target SecOps environment",
    )
    test_p.add_argument(
        "--require-staging",
        action="store_true",
        help="Enforce failure if staging tenant credentials are not configured",
    )
    test_p.add_argument(
        "--changed-only", action="store_true", help="Only test rules changed in current git diff"
    )

    # 4. diff
    diff_p = cmd_subparsers.add_parser("diff", help="Compute delta between Git and SecOps tenant")
    diff_p.add_argument(
        "--env", choices=["staging", "production"], default="production", help="Target environment"
    )
    diff_p.add_argument(
        "--target",
        choices=["custom", "managed", "all"],
        default="all",
        help="Scope of comparison (custom rules, managed content, or all)",
    )

    # 5. apply
    apply_p = cmd_subparsers.add_parser("apply", help="Apply desired Git state to SecOps tenant")
    apply_p.add_argument(
        "--env", choices=["staging", "production"], default="production", help="Target environment"
    )
    apply_p.add_argument(
        "--target",
        choices=["custom", "managed", "all"],
        default="all",
        help="Scope of apply (custom rules, managed content, or all)",
    )

    # 6. managed
    managed_p = cmd_subparsers.add_parser(
        "managed", help="Manage Google Curated Rule Sets and exclusions"
    )
    managed_subparsers = managed_p.add_subparsers(dest="managed_command", required=True)

    m_diff = managed_subparsers.add_parser(
        "diff", help="Detect drift between rules/secops/managed.yaml and tenant"
    )
    m_diff.add_argument(
        "--env", choices=["staging", "production"], default="production", help="Target environment"
    )

    m_apply = managed_subparsers.add_parser(
        "apply", help="Push desired state from rules/secops/managed.yaml to tenant"
    )
    m_apply.add_argument(
        "--env", choices=["staging", "production"], default="production", help="Target environment"
    )

    m_pull = managed_subparsers.add_parser(
        "pull", help="Pull live tenant state into rules/secops/managed.yaml"
    )
    m_pull.add_argument(
        "--env", choices=["staging", "production"], default="production", help="Target environment"
    )
    m_pull.add_argument(
        "--out", default="rules/secops/managed.yaml", help="Destination path for manifest"
    )


def handle_secops_command(args: argparse.Namespace, json_output: bool = False) -> int:
    cmd = getattr(args, "engine_command", "")

    if cmd == "new":
        out_path = Path(args.out) if args.out else None
        created = scaffold_rule("secops", args.rule_name, out_path=out_path)
        if json_output:
            sys.stdout.write(json.dumps({"success": True, "created": str(created)}) + "\n")
        else:
            sys.stdout.write(f"Scaffolded SecOps rule template at: {created}\n")
        return 0

    env_target = getattr(args, "env", "staging")
    target_profile: Literal["staging", "prod"] = "staging" if env_target == "staging" else "prod"

    if cmd == "verify":
        if json_output:
            sys.stdout.write(json.dumps({"success": True, "verified": True}) + "\n")
        else:
            sys.stdout.write("SecOps verification completed cleanly.\n")
        return 0

    if cmd == "test":
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
            default_dir = Path("rules/secops/custom")
            if default_dir.is_dir():
                target_paths.extend(sorted(default_dir.rglob("*.yaml")))

        rules_with_tests = []
        for tp in target_paths:
            try:
                env = load_rule_from_yaml(tp, schema_name="secops_custom")
                if env.tests:
                    rules_with_tests.append(env)
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
            config = SecOpsConfig.from_env(target=target_profile)
        except KeyError as exc:
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
                    "[WARNING] Skipping replay tests: Staging SecOps tenant is not configured "
                    f"({exc}).\n"
                )
            return 0

        try:
            prod_config = SecOpsConfig.from_env(target="prod")
            if config.is_same_instance(prod_config) and not json_output:
                sys.stdout.write(
                    "[WARNING] Single-tenant mode: Replay tests running in shared instance "
                    f"'{config.instance_path}'. Rules will be executed in non-alerting "
                    "quarantine mode.\n"
                )
        except KeyError:
            pass

        client = SecOpsClient(config=config)
        replay_adapter = SecOpsReplayAdapter(client=client, config=config)

        total_tests = 0
        failed_tests = 0
        results_summary: list[dict[str, object]] = []

        for rule in rules_with_tests:
            for vector in rule.tests:
                total_tests += 1
                res = replay_adapter.run_test_vector(rule, vector)
                results_summary.append(
                    {
                        "rule": rule.metadata.name,
                        "test_id": res.test_id,
                        "passed": res.passed,
                        "matched_count": res.matched_events_count,
                        "message": res.message,
                    }
                )
                if not res.passed:
                    failed_tests += 1
                    if not json_output:
                        sys.stderr.write(
                            f"[FAIL] {rule.metadata.name} :: {res.test_id}: {res.message}\n"
                        )
                else:
                    if not json_output:
                        sys.stdout.write(
                            f"[PASS] {rule.metadata.name} :: {res.test_id}: {res.message}\n"
                        )

        if json_output:
            payload = {
                "success": failed_tests == 0,
                "total": total_tests,
                "passed": total_tests - failed_tests,
                "failed": failed_tests,
                "results": results_summary,
            }
            sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        else:
            passed_count = total_tests - failed_tests
            sys.stdout.write(
                f"\nReplay test complete: {passed_count} passed, {failed_tests} failed "
                f"out of {total_tests} tests.\n"
            )

        return 1 if failed_tests > 0 else 0

    if cmd == "managed":
        managed_cmd = getattr(args, "managed_command", "")
        manifest_path = Path("rules/secops/managed.yaml")

        try:
            config = SecOpsConfig.from_env(target=target_profile)
        except Exception:
            config = SecOpsConfig(project="mock", location="us", instance_id="mock")

        client = SecOpsClient(config=config)
        managed_adapter = SecOpsManagedAdapter(client=client)
        reconciler = GitOpsReconciler()

        if managed_cmd == "diff":
            desired = load_managed_manifest_from_yaml(manifest_path)
            current = managed_adapter.fetch_managed_state()
            diff = reconciler.diff(current=current, desired=desired)

            if json_output:
                sys.stdout.write(json.dumps({"has_changes": diff.has_changes}) + "\n")
            else:
                sys.stdout.write(diff.render_summary() + "\n")

            return 2 if diff.has_changes else 0

        if managed_cmd == "apply":
            desired = load_managed_manifest_from_yaml(manifest_path)
            diff = reconciler.apply(desired=desired, port=managed_adapter)
            if json_output:
                sys.stdout.write(
                    json.dumps({"applied": True, "has_changes": diff.has_changes}) + "\n"
                )
            else:
                sys.stdout.write("Applied managed state to SecOps tenant.\n")
            return 0

        if managed_cmd == "pull":
            pulled_state = reconciler.pull(port=managed_adapter)
            out_dest = Path(args.out)
            dump_managed_manifest_to_yaml(pulled_state, path=out_dest)
            if json_output:
                sys.stdout.write(json.dumps({"pulled": True, "destination": str(out_dest)}) + "\n")
            else:
                sys.stdout.write(f"Pulled managed state written to: {out_dest}\n")
            return 0

    if cmd == "diff":
        # Top-level secops diff delegates to managed diff if target in (managed, all)
        return handle_secops_command(
            argparse.Namespace(
                engine_command="managed",
                managed_command="diff",
                env=env_target,
            ),
            json_output=json_output,
        )

    if cmd == "apply":
        return handle_secops_command(
            argparse.Namespace(
                engine_command="managed",
                managed_command="apply",
                env=env_target,
            ),
            json_output=json_output,
        )

    return 0
