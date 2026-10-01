import logging
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from graft.core.models.dataset import DatasetEnvelope, DatasetMetadata
from graft.core.models.rule import (
    BaseDeploymentConfig,
    RuleEnvelope,
    RuleMetadata,
    Runbook,
    TestEvent,
    TestVector,
)
from graft.core.ports.dataset import DatasetPort
from graft.engines.secops.adapter import SecOpsAdapter
from graft.engines.secops.client import SecOpsApiError, SecOpsClient
from graft.engines.secops.compiler import SecOpsCompilerAdapter
from graft.engines.secops.config import SecOpsConfig
from graft.engines.secops.datasets import SecOpsDatasetAdapter
from graft.engines.secops.replay import SecOpsReplayAdapter


class MockSecOpsClient(SecOpsClient):
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.responses: list[dict[str, object] | Exception] = []

    def queue_response(self, resp: dict[str, object] | Exception) -> None:
        self.responses.append(resp)

    def request(
        self,
        method: str,
        path: str,
        body: Mapping[str, object] | None = None,
        params: Mapping[str, str] | None = None,
        api_version: str | None = None,
    ) -> dict[str, object]:
        self.calls.append(
            {
                "method": method,
                "path": path,
                "body": dict(body) if body is not None else None,
                "params": dict(params) if params is not None else None,
                "api_version": api_version,
            }
        )
        if not self.responses:
            return {}
        nxt = self.responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


def _sample_dataset() -> DatasetEnvelope:
    return DatasetEnvelope(
        metadata=DatasetMetadata(
            name="known_scanner_ips",
            description="Authorized internal vulnerability scanners.",
            owners=("Security Operations",),
            tags=("network", "scanner"),
            references=("https://lopes.id/log/detection-rules-netscan-portscan/",),
        ),
        values=("10.10.0.50", "10.10.0.51"),
    )


def test_secops_dataset_adapter_conforms_to_protocol() -> None:
    client = MockSecOpsClient()
    adapter = SecOpsDatasetAdapter(client=client)
    assert isinstance(adapter, DatasetPort)

    engine_adapter = SecOpsAdapter(client=client)
    assert isinstance(engine_adapter.get_dataset(), SecOpsDatasetAdapter)


def test_create_dataset_posts_table_and_bulk_replaces_rows() -> None:
    client = MockSecOpsClient()
    client.queue_response(
        {"name": "projects/p/locations/us/instances/i/dataTables/known_scanner_ips"}
    )
    client.queue_response({"dataTableRows": []})

    adapter = SecOpsDatasetAdapter(client=client)
    ds = _sample_dataset()
    created_name = adapter.create_dataset(ds)

    assert created_name == "known_scanner_ips"
    assert len(client.calls) == 2

    create_call = client.calls[0]
    assert create_call["method"] == "POST"
    assert create_call["path"] == "dataTables"
    assert create_call["params"] == {"dataTableId": "known_scanner_ips"}
    assert create_call["api_version"] == "v1"
    assert create_call["body"] == {
        "description": "Authorized internal vulnerability scanners.",
        "columnInfo": [
            {
                "columnIndex": 0,
                "originalColumn": "value",
                "columnType": "STRING",
            }
        ],
    }

    rows_call = client.calls[1]
    assert rows_call["method"] == "POST"
    assert rows_call["path"] == "dataTables/known_scanner_ips/dataTableRows:bulkReplace"
    assert rows_call["api_version"] == "v1"
    assert rows_call["body"] == {
        "requests": [
            {"dataTableRow": {"values": ["10.10.0.50"]}},
            {"dataTableRow": {"values": ["10.10.0.51"]}},
        ]
    }


def test_update_dataset_patches_description_and_bulk_replaces_rows_with_partial_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = MockSecOpsClient()
    client.queue_response(
        {"name": "projects/p/locations/us/instances/i/dataTables/known_scanner_ips"}
    )
    client.queue_response({"dataTableRows": []})

    adapter = SecOpsDatasetAdapter(client=client)
    ds = _sample_dataset()
    adapter.update_dataset(ds)

    assert len(client.calls) == 2
    patch_call = client.calls[0]
    assert patch_call["method"] == "PATCH"
    assert patch_call["path"] == "dataTables/known_scanner_ips"
    assert patch_call["params"] == {"updateMask": "description"}
    assert patch_call["api_version"] == "v1"
    assert patch_call["body"] == {"description": "Authorized internal vulnerability scanners."}

    # Verify two-stage partial failure logs WARNING when bulkReplace fails after PATCH
    client2 = MockSecOpsClient()
    client2.queue_response(
        {"name": "projects/p/locations/us/instances/i/dataTables/known_scanner_ips"}
    )
    client2.queue_response(
        SecOpsApiError(
            "Row replacement failed",
            status_code=500,
            method="POST",
            path="dataTables/known_scanner_ips/dataTableRows:bulkReplace",
        )
    )
    adapter2 = SecOpsDatasetAdapter(client=client2)
    caplog.set_level(logging.WARNING, logger="graft.secops.datasets")
    with pytest.raises(SecOpsApiError):
        adapter2.update_dataset(ds)
    assert "partial" in caplog.text.lower() or "bulkReplace" in caplog.text


def test_list_datasets_by_names_handles_existing_and_404_missing() -> None:
    client = MockSecOpsClient()
    # 1st dataset exists
    client.queue_response(
        {
            "name": "projects/p/locations/us/instances/i/dataTables/known_scanner_ips",
            "description": "Authorized internal vulnerability scanners.",
            "columnInfo": [{"columnIndex": 0, "originalColumn": "value", "columnType": "STRING"}],
        }
    )
    client.queue_response(
        {
            "dataTableRows": [
                {"values": ["10.10.0.50"]},
                {"values": ["10.10.0.51"]},
            ]
        }
    )
    # 2nd dataset returns 404 Not Found
    client.queue_response(
        SecOpsApiError(
            "Not found",
            status_code=404,
            status="NOT_FOUND",
            method="GET",
            path="dataTables/security_assessment_ips",
        )
    )

    adapter = SecOpsDatasetAdapter(client=client)
    found = adapter.list_datasets(names=("known_scanner_ips", "security_assessment_ips"))
    assert len(found) == 1
    assert found[0].metadata.name == "known_scanner_ips"
    assert found[0].values == ("10.10.0.50", "10.10.0.51")


def test_list_datasets_discovery_filters_incompatible_tables() -> None:
    client = MockSecOpsClient()
    client.queue_response(
        {
            "dataTables": [
                {
                    "name": "projects/p/locations/us/instances/i/dataTables/known_scanner_ips",
                    "description": "Scanner IPs",
                    "columnInfo": [
                        {"columnIndex": 0, "originalColumn": "value", "columnType": "STRING"}
                    ],
                },
                {
                    "name": "projects/p/locations/us/instances/i/dataTables/multi_col_cmdb",
                    "description": "Multi-column table",
                    "columnInfo": [
                        {"columnIndex": 0, "originalColumn": "ip", "columnType": "CIDR"},
                        {"columnIndex": 1, "originalColumn": "owner", "columnType": "STRING"},
                    ],
                },
            ]
        }
    )
    client.queue_response(
        {
            "dataTableRows": [
                {"values": ["10.10.0.50"]},
            ]
        }
    )

    adapter = SecOpsDatasetAdapter(client=client)
    pulled = adapter.list_datasets(names=None)
    assert len(pulled) == 1
    assert pulled[0].metadata.name == "known_scanner_ips"
    assert pulled[0].values == ("10.10.0.50",)


def test_compiler_verify_rule_substitutes_undeployed_local_dataset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    ds_dir = tmp_path / "datasets"
    ds_dir.mkdir()
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

    client = MockSecOpsClient()
    # First :verifyRuleText fails because known_scanner_ips is not yet deployed on tenant
    client.queue_response(
        {
            "success": False,
            "compilationDiagnostics": [
                {
                    "message": "compilation error: data table (known_scanner_ips) does not exist",
                    "startLine": 7,
                    "startColumn": 5,
                    "severity": "ERROR",
                }
            ],
        }
    )
    # Second :verifyRuleText (with placeholder substituted for %known_scanner_ips.value) succeeds
    client.queue_response({"success": True})

    compiler = SecOpsCompilerAdapter(client=client)
    rule = RuleEnvelope(
        metadata=RuleMetadata(
            id="11111111-2222-3333-4444-555555555555",
            name="multiple_hosts_scanned",
            description="Detects host scanning.",
            owners=("SOC",),
            mitre={"discovery": ("T1018",)},
        ),
        logic=(
            "events:\n"
            '  $e.metadata.event_type = "NETWORK_CONNECTION"\n'
            "  not $e.principal.ip in %known_scanner_ips.value\n"
            "condition:\n"
            "  $e"
        ),
        deployment=BaseDeploymentConfig(enabled=True, alerting=True, run_frequency="live"),
        runbook=Runbook(context="c", triage="t", response="r"),
        tests=(),
    )

    result = compiler.verify_rule(rule)
    assert result.success is True
    assert len(client.calls) == 2
    second_rule_text = str(client.calls[1]["body"]["ruleText"])
    assert "%known_scanner_ips.value" not in second_rule_text


def test_replay_pre_syncs_referenced_local_datasets_to_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    ds_dir = tmp_path / "datasets"
    ds_dir.mkdir()
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

    client = MockSecOpsClient()
    # 1. Dataset pre-sync: GET dataTables/known_scanner_ips -> 404 Not Found
    client.queue_response(
        SecOpsApiError(
            "Not found", status_code=404, method="GET", path="dataTables/known_scanner_ips"
        )
    )
    # 2. POST dataTables?dataTableId=known_scanner_ips
    client.queue_response(
        {"name": "projects/s/locations/us/instances/i/dataTables/known_scanner_ips"}
    )
    # 3. POST dataTables/known_scanner_ips/dataTableRows:bulkReplace
    client.queue_response({"dataTableRows": []})
    # 4. POST :udmIngest
    client.queue_response({})
    # 5. POST rules (create quarantined rule)
    client.queue_response({"name": "projects/s/locations/us/instances/i/rules/ru_test_1"})
    # 6. PATCH rules/ru_test_1/deployment
    client.queue_response({})
    # 7. POST rules/ru_test_1:run
    client.queue_response({"detectionCount": 1})
    # 8. DELETE rules/ru_test_1
    client.queue_response({})

    staging_cfg = SecOpsConfig(project="staging-proj", location="us", instance_id="staging-inst")
    replay = SecOpsReplayAdapter(client=client, config=staging_cfg)

    rule = RuleEnvelope(
        metadata=RuleMetadata(
            id="11111111-2222-3333-4444-555555555555",
            name="multiple_hosts_scanned",
            description="Detects host scanning.",
            owners=("SOC",),
            mitre={"discovery": ("T1018",)},
        ),
        logic=(
            "events:\n"
            '  $e.metadata.event_type = "NETWORK_CONNECTION"\n'
            "  not $e.principal.ip in %known_scanner_ips.value\n"
            "condition:\n"
            "  $e"
        ),
        deployment=BaseDeploymentConfig(enabled=True, alerting=True, run_frequency="live"),
        runbook=Runbook(context="c", triage="t", response="r"),
        tests=(),
    )
    vec = TestVector(
        id="test_scan",
        description="Test scan",
        expect=1,
        events=(
            TestEvent(
                timestamp="2026-10-01T12:00:00Z",
                payload={"metadata": {"event_type": "NETWORK_CONNECTION"}},
            ),
        ),
    )

    res = replay.run_test_vector(rule, vec)
    assert res.passed is True
    paths = [c["path"] for c in client.calls]
    assert paths[:3] == [
        "dataTables/known_scanner_ips",
        "dataTables",
        "dataTables/known_scanner_ips/dataTableRows:bulkReplace",
    ]
