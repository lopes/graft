import argparse
import json
import logging
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from graft import __version__
from graft.cli.commands_core import execute_export, execute_lint, execute_update_mitre
from graft.cli.engines import discover_and_register_engines
from graft.cli.scaffold import ScaffoldError, scaffold_engine, scaffold_rule
from graft.core.env import load_env_file

logger = logging.getLogger("graft.cli")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="graft",
        description="Graft: Extensible Detection-as-Code Platform",
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug output")
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress informational messages"
    )
    parser.add_argument("--json", action="store_true", help="Format output as JSON on stdout")

    subparsers = parser.add_subparsers(dest="command")

    # 1. lint
    lint_p = subparsers.add_parser(
        "lint", help="Validate custom rules and managed manifests offline"
    )
    lint_p.add_argument(
        "paths", nargs="*", help="Files or directories to lint (default: scan rulesets/)"
    )
    lint_p.add_argument(
        "--rules-dir",
        "--rulesets-dir",
        default="rulesets",
        dest="rules_dir",
        help="Root directory of rulesets (default: rulesets)",
    )
    lint_p.add_argument("--fail-fast", action="store_true", help="Stop execution on first error")

    # 2. update-mitre
    mitre_p = subparsers.add_parser(
        "update-mitre", help="Update pinned MITRE ATT&CK Enterprise taxonomy"
    )
    mitre_p.add_argument("--source", help="URL of remote STIX bundle")

    # 3. export
    export_p = subparsers.add_parser(
        "export", help="Export metadata catalog or ATT&CK Navigator layer"
    )
    export_p.add_argument(
        "target",
        choices=["matrix", "navigator", "catalog", "metadata"],
        help="Target export artifact",
    )
    export_p.add_argument(
        "--format",
        choices=["navigator", "table", "markdown", "csv", "json"],
        help="Export format",
    )
    export_p.add_argument("--out", help="Output file path")
    export_p.add_argument(
        "--rules-dir",
        "--rulesets-dir",
        default="rulesets",
        dest="rules_dir",
        help="Root directory of rulesets (default: rulesets)",
    )
    export_p.add_argument("--engine", help="Filter export to a specific engine (e.g. secops)")
    export_p.add_argument(
        "--color",
        default="#008744",
        help="Hex color for Navigator layer gradient stop (default: #008744)",
    )

    # 4. new (engine | rule)
    new_p = subparsers.add_parser("new", help="Scaffold a new engine or detection rule")
    new_subparsers = new_p.add_subparsers(dest="new_type", required=True)

    new_engine_p = new_subparsers.add_parser(
        "engine", help="Bootstrap a new detection engine adapter"
    )
    new_engine_p.add_argument("name", help="Engine identifier slug (e.g. sentinel, crowdstrike)")

    new_rule_p = new_subparsers.add_parser("rule", help="Bootstrap a new detection rule")
    new_rule_p.add_argument("name", help="Rule identifier slug (e.g. suspicious_powershell)")
    new_rule_p.add_argument("--engine", required=True, help="Target engine (e.g. secops, sentinel)")
    new_rule_p.add_argument("--out", help="Custom output path for generated YAML rule")
    new_rule_p.add_argument(
        "--managed",
        default=None,
        metavar="MANAGED_ID",
        help="Scaffold a registered managed rule in rulesets/<engine>/managed/",
    )

    # 5. Discover & register pluggable engines (e.g., secops, sentinel, crowdstrike)
    discover_and_register_engines(subparsers)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    load_env_file()
    args_list = sys.argv[1:] if argv is None else list(argv)
    parser = build_parser()

    if not args_list:
        parser.print_help()
        return 0

    args = parser.parse_args(args_list)

    # Configure logging
    log_level = logging.WARNING if args.quiet else (logging.DEBUG if args.verbose else logging.INFO)
    logging.Formatter.converter = time.gmtime
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )

    cmd = args.command

    try:
        if cmd == "lint":
            return execute_lint(
                paths=args.paths if args.paths else None,
                rules_dir=args.rules_dir,
                fail_fast=args.fail_fast,
                json_output=args.json,
            )

        if cmd == "update-mitre":
            return execute_update_mitre(
                source_url=getattr(args, "source", None),
                json_output=args.json,
            )

        if cmd == "export":
            return execute_export(
                target=args.target,
                out_path=getattr(args, "out", None),
                format_type=getattr(args, "format", None),
                json_output=args.json,
                rules_dir=getattr(args, "rules_dir", "rulesets"),
                engine=getattr(args, "engine", None),
                color=getattr(args, "color", "#008744"),
            )

        if cmd == "new":
            if args.new_type == "engine":
                created = scaffold_engine(args.name)
                if args.json:
                    sys.stdout.write(
                        json.dumps({"success": True, "created": [str(p) for p in created.values()]})
                        + "\n"
                    )
                else:
                    sys.stdout.write(f"Scaffolded engine '{args.name}' successfully.\n")
                return 0

            if args.new_type == "rule":
                out_path = Path(args.out) if getattr(args, "out", None) else None
                managed_arg = getattr(args, "managed", None)
                is_managed = managed_arg is not None
                managed_id = managed_arg if isinstance(managed_arg, str) else None
                rule_path = scaffold_rule(
                    engine=args.engine,
                    rule_name=args.name,
                    out_path=out_path,
                    managed=is_managed,
                    managed_id=managed_id,
                )
                if args.json:
                    sys.stdout.write(json.dumps({"success": True, "path": str(rule_path)}) + "\n")
                else:
                    sys.stdout.write(f"Scaffolded rule template at: {rule_path}\n")
                return 0

        engine_handler = getattr(args, "engine_handler", None)
        if engine_handler is not None:
            return engine_handler(args, json_output=args.json)  # type: ignore[no-any-return]

    except ScaffoldError as err:
        if args.json:
            sys.stdout.write(json.dumps({"success": False, "error": str(err)}) + "\n")
        else:
            sys.stderr.write(f"Error: {err}\n")
        return 1
    except Exception as err:
        if args.json:
            sys.stdout.write(json.dumps({"success": False, "error": str(err)}) + "\n")
        elif not getattr(err, "_graft_logged", False):
            logger.error("%s", err)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
