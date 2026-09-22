import io
from pathlib import Path
from unittest.mock import MagicMock, patch

from graft.cli.main import build_parser, main
from graft.core.models.rule import BaseDeploymentConfig, RuleEnvelope, RuleMetadata, Runbook


def _make_rule(name: str, enabled: bool = True, alerting: bool = True) -> RuleEnvelope:
    return RuleEnvelope(
        metadata=RuleMetadata(id=f"id-{name}", name=name, description="desc"),
        logic="events:\n  $e\ncondition:\n  $e",
        deployment=BaseDeploymentConfig(enabled=enabled, alerting=alerting),
        runbook=Runbook(),
    )


def test_parse_diff_and_apply_all_flags() -> None:
    parser = build_parser()

    # diff default is scoped (all_rules=False)
    args = parser.parse_args(["secops", "diff"])
    assert args.all_rules is False

    # diff --all
    args = parser.parse_args(["secops", "diff", "--all"])
    assert args.all_rules is True

    # diff --full
    args = parser.parse_args(["secops", "diff", "--full"])
    assert args.all_rules is True

    # apply default is scoped (all_rules=False)
    args = parser.parse_args(["secops", "apply"])
    assert args.all_rules is False

    # apply --all
    args = parser.parse_args(["secops", "apply", "--all"])
    assert args.all_rules is True


def test_secops_diff_default_scoped_no_changes() -> None:
    stdout_capture = io.StringIO()
    with (
        patch("graft.cli.engine_controller.get_changed_files", return_value=set()),
        patch("sys.stdout", stdout_capture),
    ):
        code = main(["secops", "diff"])

    assert code == 0
    output = stdout_capture.getvalue()
    assert "No detection rules or managed manifests modified in current change scope." in output
    assert "--all" in output


def test_secops_apply_default_scoped_no_changes() -> None:
    stdout_capture = io.StringIO()
    with (
        patch("graft.cli.engine_controller.get_changed_files", return_value=set()),
        patch("sys.stdout", stdout_capture),
    ):
        code = main(["secops", "apply"])

    assert code == 0
    output = stdout_capture.getvalue()
    assert "No detection rules or managed manifests modified in current change scope." in output
    assert "--all" in output


def test_secops_diff_default_scoped_with_changed_rule(tmp_path: Path) -> None:
    rule_path = Path("rules/secops/custom/changed_rule.yaml").resolve()
    mock_desired = _make_rule("changed_rule", enabled=True, alerting=True)
    mock_remote = _make_rule("changed_rule", enabled=True, alerting=False)

    stdout_capture = io.StringIO()
    mock_deployer = MagicMock()
    mock_deployer.list_rules.return_value = (mock_remote,)

    with (
        patch("graft.cli.engine_controller.get_changed_files", return_value={rule_path}),
        patch(
            "graft.cli.engine_controller.EngineCommandController._load_custom_rules",
            return_value=(mock_desired,),
        ),
        patch("graft.engines.secops.adapter.SecOpsDeployerAdapter", return_value=mock_deployer),
        patch("graft.engines.secops.adapter.SecOpsConfig.from_env", side_effect=Exception("mock")),
        patch("sys.stdout", stdout_capture),
    ):
        code = main(["secops", "diff"])

    assert code == 2  # Changes detected
    output = stdout_capture.getvalue()
    assert "changed_rule" in output


def test_secops_diff_all_ignores_changed_files() -> None:
    mock_desired_1 = _make_rule("rule_1", enabled=True, alerting=True)
    mock_desired_2 = _make_rule("rule_2", enabled=True, alerting=True)
    mock_remote_1 = _make_rule("rule_1", enabled=True, alerting=True)
    mock_remote_2 = _make_rule("rule_2", enabled=True, alerting=False)

    stdout_capture = io.StringIO()
    mock_deployer = MagicMock()
    mock_deployer.list_rules.return_value = (mock_remote_1, mock_remote_2)

    with (
        patch("graft.cli.engine_controller.get_changed_files") as mock_get_changed,
        patch(
            "graft.cli.engine_controller.EngineCommandController._load_custom_rules",
            return_value=(mock_desired_1, mock_desired_2),
        ),
        patch("graft.engines.secops.adapter.SecOpsDeployerAdapter", return_value=mock_deployer),
        patch("graft.engines.secops.adapter.SecOpsConfig.from_env", side_effect=Exception("mock")),
        patch("sys.stdout", stdout_capture),
    ):
        code = main(["secops", "diff", "--all", "--target", "custom"])

    # In --all mode, get_changed_files is NOT called
    mock_get_changed.assert_not_called()
    assert code == 2  # rule_2 drift detected
    output = stdout_capture.getvalue()
    assert "rule_2" in output
