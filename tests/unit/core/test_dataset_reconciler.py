import logging
from pathlib import Path

import pytest

from graft.core.engine_registry import EngineRegistry
from graft.core.models.dataset import DatasetEnvelope, DatasetMetadata
from graft.core.ports.dataset import DatasetPort
from graft.core.reconciler import DatasetReconciler, DatasetsReconciliationDiff


def _make_dataset(
    name: str,
    values: tuple[str, ...] = ("10.10.0.50",),
    description: str = "Scanner IP list.",
) -> DatasetEnvelope:
    return DatasetEnvelope(
        metadata=DatasetMetadata(
            name=name,
            description=description,
            owners=("SOC",),
            tags=("network",),
            references=("https://lopes.id/log/detection-rules-netscan-portscan/",),
        ),
        values=values,
    )


class FakeDatasetAdapter:
    def __init__(
        self,
        initial: tuple[DatasetEnvelope, ...] = (),
        fail_on: str | None = None,
    ) -> None:
        self.remote: dict[str, DatasetEnvelope] = {ds.metadata.name: ds for ds in initial}
        self.fail_on = fail_on
        self.created: list[str] = []
        self.updated: list[str] = []
        self.listed_names: list[tuple[str, ...] | None] = []

    def list_datasets(
        self,
        names: tuple[str, ...] | None = None,
    ) -> tuple[DatasetEnvelope, ...]:
        self.listed_names.append(names)
        if names is None:
            return tuple(self.remote.values())
        return tuple(self.remote[n] for n in names if n in self.remote)

    def create_dataset(self, dataset: DatasetEnvelope) -> str:
        if self.fail_on == dataset.metadata.name:
            raise RuntimeError(f"Simulated API failure on {dataset.metadata.name}")
        self.created.append(dataset.metadata.name)
        self.remote[dataset.metadata.name] = dataset
        return dataset.metadata.name

    def update_dataset(self, dataset: DatasetEnvelope) -> None:
        if self.fail_on == dataset.metadata.name:
            raise RuntimeError(f"Simulated API failure on {dataset.metadata.name}")
        self.updated.append(dataset.metadata.name)
        self.remote[dataset.metadata.name] = dataset


def test_fake_dataset_adapter_conforms_to_protocol() -> None:
    adapter = FakeDatasetAdapter()
    assert isinstance(adapter, DatasetPort)


def test_dataset_reconciler_diff_coexistence_ignores_unmanaged_remote_tables() -> None:
    reconciler = DatasetReconciler()
    remote_unmanaged = _make_dataset("external_cmdb_assets", ("srv-01",))
    remote_matching = _make_dataset(
        "known_scanner_ips",
        ("10.10.0.51", "10.10.0.50"),
        description="Scanner IP list.",
    )
    desired_local = _make_dataset(
        "known_scanner_ips",
        ("10.10.0.50", "10.10.0.51"),
        description="Scanner IP list.",
    )

    diff = reconciler.diff(
        current=(remote_unmanaged, remote_matching),
        desired=(desired_local,),
    )
    assert isinstance(diff, DatasetsReconciliationDiff)
    assert diff.has_changes is False
    assert diff.datasets_to_create == ()
    assert diff.datasets_to_update == ()
    assert "No dataset changes detected" in diff.render_summary()


def test_dataset_reconciler_diff_detects_creates_and_updates() -> None:
    reconciler = DatasetReconciler()
    remote_existing = _make_dataset(
        "known_scanner_ips",
        ("10.10.0.50",),
        description="Scanner IP list.",
    )
    desired_updated = _make_dataset(
        "known_scanner_ips",
        ("10.10.0.50", "10.10.0.51"),
        description="Scanner IP list.",
    )
    desired_new = _make_dataset(
        "security_assessment_ips",
        ("192.0.2.10",),
        description="Red team assessment IPs.",
    )

    diff = reconciler.diff(
        current=(remote_existing,),
        desired=(desired_updated, desired_new),
    )
    assert diff.has_changes is True
    assert diff.datasets_to_create == (desired_new,)
    assert diff.datasets_to_update == (desired_updated,)
    summary = diff.render_summary()
    assert "[+] Dataset to create: security_assessment_ips" in summary
    assert "[~] Dataset to update: known_scanner_ips" in summary


def test_dataset_reconciler_apply_creates_and_updates_and_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="graft.reconciler")
    existing = _make_dataset("known_scanner_ips", ("10.10.0.50",))
    adapter = FakeDatasetAdapter(initial=(existing,))

    desired_updated = _make_dataset("known_scanner_ips", ("10.10.0.50", "10.10.0.51"))
    desired_new = _make_dataset("security_assessment_ips", ("192.0.2.10",))

    reconciler = DatasetReconciler()
    diff = reconciler.apply(
        desired=(desired_updated, desired_new),
        port=adapter,
    )
    assert diff.has_changes is True
    assert adapter.created == ["security_assessment_ips"]
    assert adapter.updated == ["known_scanner_ips"]
    assert adapter.listed_names == [("known_scanner_ips", "security_assessment_ips")]
    assert "Created dataset 'security_assessment_ips' in tenant" in caplog.text
    assert "Updated dataset 'known_scanner_ips' in tenant" in caplog.text


def test_dataset_reconciler_apply_logs_partial_abort_on_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="graft.reconciler")
    adapter = FakeDatasetAdapter(fail_on="security_assessment_ips")
    ds1 = _make_dataset("known_scanner_ips", ("10.10.0.50",))
    ds2 = _make_dataset("security_assessment_ips", ("192.0.2.10",))
    ds3 = _make_dataset("vip_users", ("ceo@example.com",))

    reconciler = DatasetReconciler()
    with pytest.raises(RuntimeError, match="Simulated API failure"):
        reconciler.apply(desired=(ds1, ds2, ds3), port=adapter)

    assert adapter.created == ["known_scanner_ips"]
    assert (
        "Datasets reconciliation aborted: 1/3 applied ['known_scanner_ips'], "
        "1 failed [security_assessment_ips], 1 pending ['vip_users']"
    ) in caplog.text


def test_dataset_reconciler_archived_dataset_zeroes_and_deprecates_existing_remote_table(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="graft.reconciler")
    remote_existing = _make_dataset(
        "old_assessment_ips",
        ("192.0.2.10", "198.51.100.25"),
        description="Authorized pentest IPs.",
    )
    adapter = FakeDatasetAdapter(initial=(remote_existing,))

    desired_archived = DatasetEnvelope(
        metadata=DatasetMetadata(
            name="old_assessment_ips",
            description="Deprecated on Graft",
            owners=("SOC",),
            tags=("network",),
            references=("https://lopes.id/log/detection-rules-netscan-portscan/",),
        ),
        values=(),
        deprecated=True,
    )

    reconciler = DatasetReconciler()
    diff = reconciler.diff(current=(remote_existing,), desired=(desired_archived,))
    assert diff.has_changes is True
    assert diff.datasets_to_create == ()
    assert diff.datasets_to_update == (desired_archived,)
    assert (
        "[~] Dataset to deprecate: old_assessment_ips (0 values, 'Deprecated on Graft')"
        in diff.render_summary()
    )

    applied_diff = reconciler.apply(desired=(desired_archived,), port=adapter)
    assert applied_diff.has_changes is True
    assert adapter.created == []
    assert adapter.updated == ["old_assessment_ips"]
    assert adapter.remote["old_assessment_ips"].values == ()
    assert adapter.remote["old_assessment_ips"].metadata.description == "Deprecated on Graft"
    assert "Deprecating archived dataset 'old_assessment_ips' in tenant" in caplog.text


def test_dataset_reconciler_archived_dataset_ignored_when_absent_or_already_deprecated() -> None:
    reconciler = DatasetReconciler()
    desired_archived = DatasetEnvelope(
        metadata=DatasetMetadata(
            name="old_assessment_ips",
            description="Deprecated on Graft",
            owners=("SOC",),
            tags=("network",),
            references=("https://lopes.id/log/detection-rules-netscan-portscan/",),
        ),
        values=(),
        deprecated=True,
    )

    # 1. Not present on remote -> must not create
    diff_missing = reconciler.diff(current=(), desired=(desired_archived,))
    assert diff_missing.has_changes is False
    assert diff_missing.datasets_to_create == ()
    assert diff_missing.datasets_to_update == ()

    # 2. Present on remote and already zeroed + "Deprecated on Graft" -> no changes
    remote_already_deprecated = _make_dataset(
        "old_assessment_ips",
        values=(),
        description="Deprecated on Graft",
    )
    diff_already = reconciler.diff(
        current=(remote_already_deprecated,),
        desired=(desired_archived,),
    )
    assert diff_already.has_changes is False
    assert diff_already.datasets_to_create == ()
    assert diff_already.datasets_to_update == ()


def test_engine_manifest_supports_datasets_capability(tmp_path: Path) -> None:
    eng_dir = tmp_path / "mock_eng"
    eng_dir.mkdir(parents=True)
    (eng_dir / "engine.yaml").write_text(
        """name: mock_eng
display_name: Mock Engine
description: Mock engine with dataset support
adapter_class: graft.engines.secops.adapter:SecOpsAdapter
capabilities:
  custom_rules: true
  datasets: true
  syntax_verification: false
  managed_rules: false
  replay_testing: false
""",
        encoding="utf-8",
    )
    reg = EngineRegistry(engines_dir=tmp_path, strict=True)
    manifest = reg.get("mock_eng")
    assert manifest.capabilities.datasets is True
