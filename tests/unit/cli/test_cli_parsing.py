import tomllib
from pathlib import Path

import pytest

from graft import __version__
from graft.cli.main import build_parser


def test_parse_root_flags() -> None:
    parser = build_parser()
    args = parser.parse_args(["--verbose", "--json"])
    assert args.verbose is True
    assert args.json is True
    assert args.quiet is False


def test_parse_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert f"graft {__version__}" in captured.out


def test_pyproject_release_metadata() -> None:
    pyproject_path = Path("pyproject.toml")
    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    project = data["project"]
    assert project["version"] == __version__
    assert "authors" in project and len(project["authors"]) >= 1
    assert "keywords" in project and len(project["keywords"]) >= 3
    assert "classifiers" in project and len(project["classifiers"]) >= 3
    assert "urls" in project
    assert "Repository" in project["urls"]
    assert "Documentation" in project["urls"]
    assert "Issues" in project["urls"]


def test_parse_lint_command() -> None:
    parser = build_parser()
    args = parser.parse_args(
        ["lint", "rulesets/secops/custom/gcp_iam_service_account_key_create.yaml", "--fail-fast"]
    )
    assert args.command == "lint"
    assert args.paths == ["rulesets/secops/custom/gcp_iam_service_account_key_create.yaml"]
    assert args.fail_fast is True


def test_parse_new_engine_command() -> None:
    parser = build_parser()
    args = parser.parse_args(["new", "engine", "sentinel"])
    assert args.command == "new"
    assert args.new_type == "engine"
    assert args.name == "sentinel"


def test_parse_new_rule_command() -> None:
    parser = build_parser()
    args = parser.parse_args(["new", "rule", "suspicious_powershell", "--engine", "secops"])
    assert args.command == "new"
    assert args.new_type == "rule"
    assert args.name == "suspicious_powershell"
    assert args.engine == "secops"


def test_parse_secops_subcommands() -> None:
    parser = build_parser()

    # new
    args = parser.parse_args(["secops", "new", "test_rule"])
    assert args.command == "secops"
    assert args.engine_command == "new"
    assert args.rule_name == "test_rule"

    # verify
    args = parser.parse_args(["secops", "verify", "--env", "staging"])
    assert args.command == "secops"
    assert args.engine_command == "verify"
    assert args.env == "staging"

    # test
    args = parser.parse_args(["secops", "test", "--require-staging", "--changed-only"])
    assert args.command == "secops"
    assert args.engine_command == "test"
    assert args.require_staging is True
    assert args.changed_only is True

    # diff
    args = parser.parse_args(["secops", "diff", "--env", "production", "--target", "managed"])
    assert args.command == "secops"
    assert args.engine_command == "diff"
    assert args.env == "production"
    assert args.target == "managed"

    # apply
    args = parser.parse_args(["secops", "apply", "--env", "staging"])
    assert args.command == "secops"
    assert args.engine_command == "apply"

    # managed pull
    args = parser.parse_args(["secops", "managed", "pull", "--env", "production"])
    assert args.command == "secops"
    assert args.engine_command == "managed"
    assert args.managed_command == "pull"
    assert args.env == "production"


def test_dynamic_engine_discovery() -> None:
    import argparse
    from unittest.mock import MagicMock, patch

    from graft.cli.engines import discover_and_register_engines

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")

    mock_engine_mod = MagicMock()
    with (
        patch("pkgutil.iter_modules", return_value=[(None, "sentinel", False)]),
        patch("importlib.import_module", return_value=mock_engine_mod),
    ):
        discover_and_register_engines(subparsers)
        mock_engine_mod.register_engine.assert_called_once_with(subparsers)
