import argparse
import json
import logging
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from graft import __version__
from graft.cli.commands_core import (
    execute_engines,
    execute_export,
    execute_lint,
    execute_mitre_coverage,
    execute_mitre_gaps,
    execute_mitre_inspect,
    execute_update_mitre,
)
from graft.cli.engines import discover_and_register_engines
from graft.cli.scaffold import ScaffoldError, scaffold_dataset, scaffold_engine, scaffold_rule
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
        "lint", help="Validate custom rules, datasets, and managed manifests offline"
    )
    lint_p.add_argument(
        "paths",
        nargs="*",
        help="Files or directories to lint (default: scan datasets/ and rulesets/)",
    )
    lint_p.add_argument(
        "--rules-dir",
        "--rulesets-dir",
        default="rulesets",
        dest="rules_dir",
        help="Root directory of rulesets (default: rulesets)",
    )
    lint_p.add_argument(
        "--datasets-dir",
        default=None,
        dest="datasets_dir",
        help="Root directory of datasets (default: datasets)",
    )
    lint_p.add_argument("--fail-fast", action="store_true", help="Stop execution on first error")

    # 2. mitre (coverage | gaps | inspect | update)
    mitre_root_p = subparsers.add_parser(
        "mitre",
        help="MITRE ATT&CK coverage, gap analysis, entity inspection, and taxonomy updates",
    )
    mitre_subparsers = mitre_root_p.add_subparsers(dest="mitre_command", required=True)

    mitre_cov_p = mitre_subparsers.add_parser(
        "coverage",
        help="Inspect repository MITRE ATT&CK coverage with optional STIX enrichments and filters",
    )
    mitre_cov_p.add_argument("--engine", help="Filter rules to a specific engine")
    mitre_cov_p.add_argument("--platform", help="Filter techniques by MITRE platform (e.g. IaaS)")
    mitre_cov_p.add_argument(
        "--group", help="Filter techniques by Threat Group ID or alias (e.g. G0096, APT41)"
    )
    mitre_cov_p.add_argument("--tactic", help="Filter by MITRE tactic ID or shortname")
    mitre_cov_p.add_argument(
        "--technique", help="Filter to a specific technique ID (e.g. T1098.001)"
    )
    mitre_cov_p.add_argument(
        "--det", help="Filter to a specific Detection Strategy ID (e.g. DET0010)"
    )
    mitre_cov_p.add_argument(
        "--data-component",
        dest="data_component",
        help="Filter by MITRE Data Component ID or name (e.g. DC0064)",
    )
    mitre_cov_p.add_argument("--tag", help="Filter rules by tag (e.g. aws, gcp, workspace)")
    mitre_cov_p.add_argument(
        "--enrich",
        action="store_true",
        help="Include DET strategies, DC data components, M mitigations, and group counts",
    )
    mitre_cov_p.add_argument(
        "--format",
        choices=["table", "json", "csv", "markdown"],
        help="Output format (default: table or json when --json is set)",
    )
    mitre_cov_p.add_argument("--out", help="Output file path")
    mitre_cov_p.add_argument(
        "--rules-dir",
        "--rulesets-dir",
        default="rulesets",
        dest="rules_dir",
        help="Root directory of rulesets (default: rulesets)",
    )

    mitre_gaps_p = mitre_subparsers.add_parser(
        "gaps",
        help="Analyze uncovered and partially covered MITRE techniques ranked by threat prevalence",
    )
    mitre_gaps_p.add_argument("--engine", help="Filter rules to a specific engine")
    mitre_gaps_p.add_argument(
        "--platform", help="Scope gaps to a MITRE platform (e.g. IaaS, Google Workspace, Linux)"
    )
    mitre_gaps_p.add_argument(
        "--group", help="Scope gaps to a Threat Group ID or alias (e.g. G0096, APT41)"
    )
    mitre_gaps_p.add_argument("--tactic", help="Scope gaps to a MITRE tactic ID or shortname")
    mitre_gaps_p.add_argument(
        "--data-component",
        dest="data_component",
        help="Scope gaps to a MITRE Data Component ID or name",
    )
    mitre_gaps_p.add_argument(
        "--top",
        type=int,
        default=None,
        help="Limit output to top N highest-prevalence gaps (default: 25 in table mode)",
    )
    mitre_gaps_p.add_argument(
        "--format",
        choices=["table", "json", "csv", "markdown"],
        help="Output format (default: table or json when --json is set)",
    )
    mitre_gaps_p.add_argument("--out", help="Output file path")
    mitre_gaps_p.add_argument(
        "--rules-dir",
        "--rulesets-dir",
        default="rulesets",
        dest="rules_dir",
        help="Root directory of rulesets (default: rulesets)",
    )

    mitre_insp_p = mitre_subparsers.add_parser(
        "inspect",
        help=(
            "Inspect MITRE techniques (Txxxx), strategies (DETxxxx), analytics (ANxxxx), "
            "groups (Gxxxx), mitigations (Mxxxx), or data components (DCxxxx)"
        ),
    )
    mitre_insp_p.add_argument(
        "targets",
        nargs="+",
        help="MITRE IDs or threat group aliases to inspect (e.g. T1098.001 DET0050 G0096)",
    )
    mitre_insp_p.add_argument(
        "--platform", help="Filter analytics or group techniques by MITRE platform"
    )
    mitre_insp_p.add_argument(
        "--analytics",
        action="store_true",
        help="Include full ANxxxx analytics, log sources, and tunable mutable elements",
    )
    mitre_insp_p.add_argument(
        "--groups",
        action="store_true",
        help="Expand full list of associated Gxxxx threat groups",
    )
    mitre_insp_p.add_argument(
        "--full",
        action="store_true",
        help="Expand both ANxxxx analytics and full Gxxxx threat group lists",
    )
    mitre_insp_p.add_argument(
        "--rules-dir",
        "--rulesets-dir",
        default="rulesets",
        dest="rules_dir",
        help="Root directory of rulesets (default: rulesets)",
    )

    mitre_upd_p = mitre_subparsers.add_parser(
        "update",
        help="Update pinned MITRE ATT&CK Enterprise taxonomy and analytics bundle",
    )
    mitre_upd_p.add_argument("--source", help="URL of remote STIX bundle")
    mitre_upd_p.add_argument(
        "--version", help="Specific ATT&CK Enterprise version to fetch (e.g. 20.0, 19.2)"
    )
    mitre_upd_p.add_argument(
        "--check",
        action="store_true",
        help="Check if a newer MITRE ATT&CK version is available upstream without updating files",
    )

    # 3. export
    export_p = subparsers.add_parser(
        "export", help="Export metadata catalog, datasets, or ATT&CK Navigator layer"
    )
    export_p.add_argument(
        "target",
        choices=["navigator", "matrix", "mitre", "catalog", "metadata", "datasets"],
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
    export_p.add_argument(
        "--datasets-dir",
        default="datasets",
        dest="datasets_dir",
        help="Root directory of datasets (default: datasets)",
    )
    export_p.add_argument("--engine", help="Filter export to a specific engine (e.g. secops)")
    export_p.add_argument(
        "--color",
        default="#008744",
        help="Hex color for Navigator layer gradient stop (default: #008744)",
    )
    export_p.add_argument("--platform", help="Filter export by MITRE platform")
    export_p.add_argument("--group", help="Filter export by MITRE Threat Group ID or alias")
    export_p.add_argument(
        "--data-component",
        dest="data_component",
        help="Filter export by MITRE Data Component ID or name",
    )
    export_p.add_argument(
        "--enrich",
        action="store_true",
        help="Include MITRE platforms, data components, mitigations, and group counts",
    )
    export_p.add_argument(
        "--include-gaps",
        action="store_true",
        dest="include_gaps",
        help="Include uncovered/partial in-scope techniques (score: 0) in Navigator layer",
    )

    # 4. engines
    subparsers.add_parser(
        "engines", help="List registered detection engines, capabilities, and schemas"
    )

    # 4. new (engine | rule | dataset)
    new_p = subparsers.add_parser("new", help="Scaffold a new engine, detection rule, or dataset")
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

    new_dataset_p = new_subparsers.add_parser(
        "dataset", help="Bootstrap a new engine-agnostic dataset"
    )
    new_dataset_p.add_argument("name", help="Dataset identifier slug (e.g. known_scanner_ips)")
    new_dataset_p.add_argument("--out", help="Custom output path for generated YAML dataset")

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
                datasets_dir=getattr(args, "datasets_dir", None),
                fail_fast=args.fail_fast,
                json_output=args.json,
            )

        if cmd == "mitre":
            m_cmd = getattr(args, "mitre_command", None)
            if m_cmd == "coverage":
                return execute_mitre_coverage(
                    rules_dir=getattr(args, "rules_dir", "rulesets"),
                    engine=getattr(args, "engine", None),
                    platform=getattr(args, "platform", None),
                    group=getattr(args, "group", None),
                    tactic=getattr(args, "tactic", None),
                    technique=getattr(args, "technique", None),
                    det=getattr(args, "det", None),
                    data_component=getattr(args, "data_component", None),
                    tag=getattr(args, "tag", None),
                    enrich=bool(getattr(args, "enrich", False)),
                    format_type=getattr(args, "format", None),
                    out_path=getattr(args, "out", None),
                    json_output=args.json,
                )
            if m_cmd == "gaps":
                return execute_mitre_gaps(
                    rules_dir=getattr(args, "rules_dir", "rulesets"),
                    engine=getattr(args, "engine", None),
                    platform=getattr(args, "platform", None),
                    group=getattr(args, "group", None),
                    tactic=getattr(args, "tactic", None),
                    data_component=getattr(args, "data_component", None),
                    top=getattr(args, "top", None),
                    format_type=getattr(args, "format", None),
                    out_path=getattr(args, "out", None),
                    json_output=args.json,
                )
            if m_cmd == "inspect":
                return execute_mitre_inspect(
                    targets=list(getattr(args, "targets", [])),
                    rules_dir=getattr(args, "rules_dir", "rulesets"),
                    platform=getattr(args, "platform", None),
                    include_analytics=bool(getattr(args, "analytics", False)),
                    include_groups=bool(getattr(args, "groups", False)),
                    full=bool(getattr(args, "full", False)),
                    json_output=args.json,
                )
            if m_cmd == "update":
                return execute_update_mitre(
                    source_url=getattr(args, "source", None),
                    json_output=args.json,
                    version=getattr(args, "version", None),
                    check_only=bool(getattr(args, "check", False)),
                )

        if cmd == "export":
            return execute_export(
                target=args.target,
                out_path=getattr(args, "out", None),
                format_type=getattr(args, "format", None),
                json_output=args.json,
                rules_dir=getattr(args, "rules_dir", "rulesets"),
                datasets_dir=getattr(args, "datasets_dir", "datasets"),
                engine=getattr(args, "engine", None),
                color=getattr(args, "color", "#008744"),
                platform=getattr(args, "platform", None),
                group=getattr(args, "group", None),
                data_component=getattr(args, "data_component", None),
                enrich=bool(getattr(args, "enrich", False)),
                include_gaps=bool(getattr(args, "include_gaps", False)),
            )

        if cmd == "engines":
            return execute_engines(json_output=args.json)

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

            if args.new_type == "dataset":
                out_path = Path(args.out) if getattr(args, "out", None) else None
                dataset_path = scaffold_dataset(
                    dataset_name=args.name,
                    out_path=out_path,
                )
                if args.json:
                    sys.stdout.write(
                        json.dumps({"success": True, "path": str(dataset_path)}) + "\n"
                    )
                else:
                    sys.stdout.write(f"Scaffolded dataset template at: {dataset_path}\n")
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
