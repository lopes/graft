import argparse
import json
from pathlib import Path

import pytest

from graft.cli.engine_controller import EngineCommandController, register_engine_commands
from graft.core.engine_registry import EngineRegistry
from graft.core.loader import load_dataset_from_yaml
from graft.core.models.dataset import DatasetEnvelope, DatasetMetadata
from graft.core.models.engine import EngineCapabilities, EngineManifest
from graft.core.models.managed import ManagedState
from graft.core.models.rule import RuleEnvelope
from graft.core.ports.compiler import RuleCompilerPort
from graft.core.ports.dataset import DatasetPort
from graft.core.ports.deployer import RuleDeployerPort
from graft.core.ports.engine import EngineAdapter
from graft.core.ports.managed import ManagedEnginePort
from graft.core.ports.replay import ReplayHarnessPort


class RecordingOrderAdapter(EngineAdapter):
    def __init__(
        self,
        call_order: list[str],
        remote_datasets: tuple[DatasetEnvelope, ...] = (),
        fail_dataset: bool = False,
    ) -> None:
        self.call_order = call_order
        self._remote_datasets = {d.metadata.name: d for d in remote_datasets}
        self._fail_dataset = fail_dataset
        self._dataset_port = _RecordingDatasetPort(
            self.call_order, self._remote_datasets, fail_dataset
        )
        self._deployer_port = _RecordingDeployerPort(self.call_order)
        self._managed_port = _RecordingManagedPort(self.call_order)

    def get_compiler(self) -> RuleCompilerPort | None:
        return None

    def get_deployer(self) -> RuleDeployerPort | None:
        return self._deployer_port

    def get_managed(self) -> ManagedEnginePort | None:
        return self._managed_port

    def get_replay(self) -> ReplayHarnessPort | None:
        return None

    def get_dataset(self) -> DatasetPort | None:
        return self._dataset_port

    def load_managed_manifest(self, path: Path) -> ManagedState | None:
        return ManagedState(rulesets=(), exclusions=())

    def dump_managed_manifest(self, state: ManagedState, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("categories: []\nexclusions: []\n", encoding="utf-8")


class _RecordingDatasetPort(DatasetPort):
    def __init__(
        self,
        call_order: list[str],
        remote: dict[str, DatasetEnvelope],
        fail: bool = False,
    ) -> None:
        self.call_order = call_order
        self.remote = remote
        self.fail = fail

    def list_datasets(
        self,
        names: tuple[str, ...] | None = None,
    ) -> tuple[DatasetEnvelope, ...]:
        self.call_order.append("datasets:list")
        if names is None:
            return tuple(self.remote.values())
        return tuple(self.remote[n] for n in names if n in self.remote)

    def create_dataset(self, dataset: DatasetEnvelope) -> str:
        self.call_order.append(f"datasets:create:{dataset.metadata.name}")
        if self.fail:
            raise RuntimeError("Dataset creation failed")
        return dataset.metadata.name

    def update_dataset(self, dataset: DatasetEnvelope) -> None:
        self.call_order.append(f"datasets:update:{dataset.metadata.name}")
        if self.fail:
            raise RuntimeError("Dataset update failed")


class _RecordingDeployerPort(RuleDeployerPort):
    def __init__(self, call_order: list[str]) -> None:
        self.call_order = call_order

    def list_rules(self) -> tuple[RuleEnvelope, ...]:
        self.call_order.append("custom:list")
        return ()

    def create_rule(self, rule: RuleEnvelope) -> str:
        self.call_order.append(f"custom:create:{rule.metadata.name}")
        return rule.metadata.id

    def update_rule(self, rule: RuleEnvelope) -> None:
        self.call_order.append(f"custom:update:{rule.metadata.name}")

    def delete_rule(self, rule_id: str) -> None:
        pass

    def set_rule_state(self, rule_id: str, enabled: bool, alerting: bool) -> None:
        pass


class _RecordingManagedPort(ManagedEnginePort):
    def __init__(self, call_order: list[str]) -> None:
        self.call_order = call_order

    def fetch_managed_state(self) -> ManagedState:
        self.call_order.append("managed:fetch")
        return ManagedState(rulesets=(), exclusions=())

    def set_ruleset_deployment(
        self,
        ruleset_id: str,
        deployment_type: str,
        enabled: bool,
        alerting: bool,
        category: str | None = None,
    ) -> None:
        pass

    def create_exclusion(self, exclusion: object) -> str:
        return ""

    def update_exclusion(self, exclusion: object) -> None:
        pass

    def delete_exclusion(self, exclusion_id: str) -> None:
        pass

    def apply_managed_state(self, desired_state: ManagedState) -> None:
        pass


def _setup_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    ds_dir = tmp_path / "datasets"
    ds_dir.mkdir(parents=True)
    (ds_dir / "known_scanner_ips.yaml").write_text(
        """metadata:
  name: "known_scanner_ips"
  description: "Authorized internal vulnerability scanners."
  owners: ["SOC"]
  tags: ["network"]
  references: ["https://lopes.id/log/detection-rules-netscan-portscan/"]
values:
  - "10.10.0.50"
""",
        encoding="utf-8",
    )

    custom_dir = tmp_path / "rulesets" / "secops" / "custom"
    custom_dir.mkdir(parents=True)
    (custom_dir / "multiple_hosts_scanned.yaml").write_text(
        """metadata:
  id: "11111111-2222-3333-4444-555555555555"
  name: "multiple_hosts_scanned"
  description: "Detects a source scanning multiple hosts."
  owners: ["SOC"]
  mitre:
    discovery: ["T1018"]
  tags: ["network"]
  references: ["https://lopes.id/log/detection-rules-netscan-portscan/"]
logic: |
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    not $e.principal.ip in %known_scanner_ips.value
  condition:
    $e
deployment:
  enabled: true
  alerting: true
  run_frequency: "live"
runbook:
  context: "Context."
  triage: "Triage."
  response: "Response."
tests: []
""",
        encoding="utf-8",
    )

    managed_dir = tmp_path / "rulesets" / "secops" / "managed"
    managed_dir.mkdir(parents=True)
    (managed_dir / "index.yaml").write_text("categories: []\nexclusions: []\n", encoding="utf-8")


def _make_manifest() -> EngineManifest:
    return EngineManifest(
        name="secops",
        display_name="Google SecOps",
        description="Google SecOps Engine",
        adapter_class="graft.engines.secops.adapter:SecOpsAdapter",
        capabilities=EngineCapabilities(
            custom_rules=True,
            datasets=True,
            syntax_verification=True,
            managed_rules=True,
            replay_testing=True,
        ),
    )


def test_apply_executes_datasets_before_custom_rules_and_managed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _setup_workspace(tmp_path, monkeypatch)
    call_order: list[str] = []
    adapter = RecordingOrderAdapter(call_order)

    reg = EngineRegistry()
    monkeypatch.setattr(reg, "load_adapter", lambda name, env="production": adapter)
    controller = EngineCommandController(_make_manifest(), reg)

    args = argparse.Namespace(
        engine_command="apply",
        env="production",
        target="all",
        all_rules=True,
    )
    rc = controller.execute(args, json_output=True)
    assert rc == 0
    assert call_order == [
        "datasets:list",
        "datasets:create:known_scanner_ips",
        "custom:list",
        "custom:create:multiple_hosts_scanned",
        "managed:fetch",
    ]
    out = json.loads(capsys.readouterr().out)
    assert out["datasets"]["created"] == 1
    assert out["custom"]["created"] == 1
    assert out["managed"]["applied"] is True


def test_apply_aborts_custom_rules_when_dataset_sync_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup_workspace(tmp_path, monkeypatch)
    call_order: list[str] = []
    adapter = RecordingOrderAdapter(call_order, fail_dataset=True)

    reg = EngineRegistry()
    monkeypatch.setattr(reg, "load_adapter", lambda name, env="production": adapter)
    controller = EngineCommandController(_make_manifest(), reg)

    args = argparse.Namespace(
        engine_command="apply",
        env="production",
        target="all",
        all_rules=True,
    )
    with pytest.raises(RuntimeError, match="Dataset creation failed"):
        controller.execute(args, json_output=False)

    assert call_order == ["datasets:list", "datasets:create:known_scanner_ips"]


def test_scoped_diff_detects_modified_dataset_when_no_rules_changed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _setup_workspace(tmp_path, monkeypatch)
    ds_file = (tmp_path / "datasets" / "known_scanner_ips.yaml").resolve()
    monkeypatch.setattr(
        "graft.cli.engine_controller.get_changed_files",
        lambda: {ds_file},
    )
    call_order: list[str] = []
    adapter = RecordingOrderAdapter(call_order)

    reg = EngineRegistry()
    monkeypatch.setattr(reg, "load_adapter", lambda name, env="production": adapter)
    controller = EngineCommandController(_make_manifest(), reg)

    args = argparse.Namespace(
        engine_command="diff",
        env="production",
        target="all",
        all_rules=False,
    )
    rc = controller.execute(args, json_output=True)
    assert rc == 2
    assert call_order == ["datasets:list"]
    payload = json.loads(capsys.readouterr().out)
    assert payload["datasets"]["has_changes"] is True
    assert payload["datasets"]["datasets_to_create"] == ["known_scanner_ips"]
    assert "custom" not in payload


def test_pull_excludes_datasets_on_target_all_and_pulls_on_target_datasets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    remote_ds = DatasetEnvelope(
        metadata=DatasetMetadata(
            name="known_scanner_ips",
            description="Pulled scanner IPs.",
            owners=("SOC",),
            tags=("secops", "dataset"),
            references=(
                "https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.dataTables",
            ),
        ),
        values=("10.10.0.50",),
    )
    call_order: list[str] = []
    adapter = RecordingOrderAdapter(call_order, remote_datasets=(remote_ds,))

    reg = EngineRegistry()
    monkeypatch.setattr(reg, "load_adapter", lambda name, env="production": adapter)
    controller = EngineCommandController(_make_manifest(), reg)

    # 1. Default pull (--target all) must NOT pull datasets
    args_all = argparse.Namespace(
        engine_command="pull",
        env="production",
        target="all",
        force=False,
        out_dir=str(tmp_path / "rulesets/secops/custom"),
        out_manifest=str(tmp_path / "rulesets/secops/managed/index.yaml"),
        out_datasets_dir=str(tmp_path / "datasets"),
    )
    rc_all = controller.execute(args_all, json_output=True)
    assert rc_all == 0
    assert "datasets:list" not in call_order
    assert not (tmp_path / "datasets" / "known_scanner_ips.yaml").exists()
    capsys.readouterr()

    # 2. Explicit --target datasets pulls compatible datasets into datasets/
    args_ds = argparse.Namespace(
        engine_command="pull",
        env="production",
        target="datasets",
        force=False,
        out_dir=str(tmp_path / "rulesets/secops/custom"),
        out_manifest=str(tmp_path / "rulesets/secops/managed/index.yaml"),
        out_datasets_dir=str(tmp_path / "datasets"),
    )
    rc_ds = controller.execute(args_ds, json_output=True)
    assert rc_ds == 0
    assert "datasets:list" in call_order
    pulled_file = tmp_path / "datasets" / "known_scanner_ips.yaml"
    assert pulled_file.is_file()
    loaded = load_dataset_from_yaml(pulled_file)
    assert loaded.metadata.name == "known_scanner_ips"
    assert loaded.values == ("10.10.0.50",)


def test_register_engine_commands_includes_datasets_target() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    manifest = _make_manifest()
    register_engine_commands(subparsers, manifest, EngineRegistry())

    parsed_diff = parser.parse_args(["secops", "diff", "--target", "datasets"])
    assert parsed_diff.target == "datasets"

    parsed_apply = parser.parse_args(["secops", "apply", "--target", "datasets"])
    assert parsed_apply.target == "datasets"

    parsed_pull = parser.parse_args(["secops", "pull", "--target", "datasets"])
    assert parsed_pull.target == "datasets"
