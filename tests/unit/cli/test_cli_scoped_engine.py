import argparse
import io
from pathlib import Path
from unittest.mock import MagicMock, patch

from graft.cli.engine_controller import EngineCommandController, register_engine_commands
from graft.core.engine_registry import EngineRegistry
from graft.core.models.engine import EngineCapabilities, EngineManifest
from graft.core.models.rule import BaseDeploymentConfig, RuleEnvelope, RuleMetadata, Runbook


def _make_manifest() -> EngineManifest:
    return EngineManifest(
        name="siem_alpha",
        display_name="SIEM Alpha",
        description="SIEM Alpha Engine",
        adapter_class="graft.engines.siem_alpha.adapter:SiemAlphaAdapter",
        capabilities=EngineCapabilities(
            custom_rules=True,
            datasets=True,
            syntax_verification=True,
            managed_rules=True,
            replay_testing=True,
        ),
    )


def _make_rule(name: str, enabled: bool = True, alerting: bool = True) -> RuleEnvelope:
    return RuleEnvelope(
        metadata=RuleMetadata(id=f"id-{name}", name=name, description="desc"),
        logic="events:\n  $e\ncondition:\n  $e",
        deployment=BaseDeploymentConfig(enabled=enabled, alerting=alerting),
        runbook=Runbook(),
    )


def test_parse_diff_and_apply_all_flags() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    register_engine_commands(subparsers, _make_manifest(), EngineRegistry())

    # diff default is scoped (all_rules=False)
    args = parser.parse_args(["siem_alpha", "diff"])
    assert args.all_rules is False

    # diff --all
    args = parser.parse_args(["siem_alpha", "diff", "--all"])
    assert args.all_rules is True

    # diff --full
    args = parser.parse_args(["siem_alpha", "diff", "--full"])
    assert args.all_rules is True

    # apply default is scoped (all_rules=False)
    args = parser.parse_args(["siem_alpha", "apply"])
    assert args.all_rules is False

    # apply --all
    args = parser.parse_args(["siem_alpha", "apply", "--all"])
    assert args.all_rules is True


def test_engine_diff_default_scoped_no_changes() -> None:
    stdout_capture = io.StringIO()
    reg = EngineRegistry()
    controller = EngineCommandController(_make_manifest(), reg)
    args = argparse.Namespace(
        engine_command="diff",
        env="production",
        target="all",
        all_rules=False,
    )
    with (
        patch.object(reg, "load_adapter", return_value=MagicMock()),
        patch("graft.cli.engine_controller.get_changed_files", return_value=set()),
        patch("sys.stdout", stdout_capture),
    ):
        code = controller.execute(args, json_output=False)

    assert code == 0
    output = stdout_capture.getvalue()
    assert "No detection rules or managed manifests modified in current change scope." in output
    assert "--all" in output


def test_engine_apply_default_scoped_no_changes() -> None:
    stdout_capture = io.StringIO()
    reg = EngineRegistry()
    controller = EngineCommandController(_make_manifest(), reg)
    args = argparse.Namespace(
        engine_command="apply",
        env="production",
        target="all",
        all_rules=False,
    )
    with (
        patch.object(reg, "load_adapter", return_value=MagicMock()),
        patch("graft.cli.engine_controller.get_changed_files", return_value=set()),
        patch("sys.stdout", stdout_capture),
    ):
        code = controller.execute(args, json_output=False)

    assert code == 0
    output = stdout_capture.getvalue()
    assert "No detection rules or managed manifests modified in current change scope." in output
    assert "--all" in output


def test_engine_diff_default_scoped_with_changed_rule() -> None:
    rule_path = Path("rulesets/siem_alpha/custom/changed_rule.yaml").resolve()
    mock_desired = _make_rule("changed_rule", enabled=True, alerting=True)
    mock_remote = _make_rule("changed_rule", enabled=True, alerting=False)

    stdout_capture = io.StringIO()
    mock_deployer = MagicMock()
    mock_deployer.list_rules.return_value = (mock_remote,)
    mock_adapter = MagicMock()
    mock_adapter.get_deployer.return_value = mock_deployer

    reg = EngineRegistry()
    controller = EngineCommandController(_make_manifest(), reg)
    args = argparse.Namespace(
        engine_command="diff",
        env="production",
        target="all",
        all_rules=False,
    )

    with (
        patch("graft.cli.engine_controller.get_changed_files", return_value={rule_path}),
        patch.object(
            EngineCommandController,
            "_load_custom_rules",
            return_value=(mock_desired,),
        ),
        patch.object(reg, "load_adapter", return_value=mock_adapter),
        patch("sys.stdout", stdout_capture),
    ):
        code = controller.execute(args, json_output=False)

    assert code == 2  # Changes detected
    output = stdout_capture.getvalue()
    assert "changed_rule" in output


def test_engine_diff_all_ignores_changed_files() -> None:
    mock_desired_1 = _make_rule("rule_1", enabled=True, alerting=True)
    mock_desired_2 = _make_rule("rule_2", enabled=True, alerting=True)
    mock_remote_1 = _make_rule("rule_1", enabled=True, alerting=True)
    mock_remote_2 = _make_rule("rule_2", enabled=True, alerting=False)

    stdout_capture = io.StringIO()
    mock_deployer = MagicMock()
    mock_deployer.list_rules.return_value = (mock_remote_1, mock_remote_2)
    mock_adapter = MagicMock()
    mock_adapter.get_deployer.return_value = mock_deployer

    reg = EngineRegistry()
    controller = EngineCommandController(_make_manifest(), reg)
    args = argparse.Namespace(
        engine_command="diff",
        env="production",
        target="custom",
        all_rules=True,
    )

    with (
        patch("graft.cli.engine_controller.get_changed_files") as mock_get_changed,
        patch.object(
            EngineCommandController,
            "_load_custom_rules",
            return_value=(mock_desired_1, mock_desired_2),
        ),
        patch.object(reg, "load_adapter", return_value=mock_adapter),
        patch("sys.stdout", stdout_capture),
    ):
        code = controller.execute(args, json_output=False)

    mock_get_changed.assert_not_called()
    assert code == 2  # rule_2 drift detected
    output = stdout_capture.getvalue()
    assert "rule_2" in output


def test_engine_diff_scoped_ignores_registered_managed_rule_changes() -> None:
    registered_managed_path = Path(
        "rulesets/siem_alpha/managed/gcti_breach_network_indicator_matched.yaml"
    ).resolve()
    stdout_capture = io.StringIO()
    reg = EngineRegistry()
    controller = EngineCommandController(_make_manifest(), reg)
    args = argparse.Namespace(
        engine_command="diff",
        env="production",
        target="all",
        all_rules=False,
    )
    with (
        patch.object(reg, "load_adapter", return_value=MagicMock()),
        patch(
            "graft.cli.engine_controller.get_changed_files",
            return_value={registered_managed_path},
        ),
        patch("sys.stdout", stdout_capture),
    ):
        code = controller.execute(args, json_output=False)

    assert code == 0
    output = stdout_capture.getvalue()
    assert "No detection rules or managed manifests modified in current change scope." in output
