import json
from unittest.mock import MagicMock, patch

import pytest

from graft.cli.main import main
from graft.core.ports.replay import ReplayResult


def test_cli_test_graceful_degradation_when_staging_missing(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    for var in (
        "GRAFT_SECOPS_STAGING_PROJECT",
        "GRAFT_SECOPS_PROJECT",
        "GRAFT_SECOPS_PROD_PROJECT",
        "GRAFT_STAGING_PROJECT",
        "GRAFT_PROJECT",
        "GRAFT_PROD_PROJECT",
    ):
        monkeypatch.delenv(var, raising=False)

    exit_code = main(
        ["secops", "test", "rules/secops/custom/gcp_iam_service_account_key_create.yaml"]
    )
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "WARNING" in captured.out or "Skipping" in captured.out


def test_cli_test_require_staging_fails_when_staging_missing(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    for var in (
        "GRAFT_SECOPS_STAGING_PROJECT",
        "GRAFT_SECOPS_PROJECT",
        "GRAFT_SECOPS_PROD_PROJECT",
        "GRAFT_STAGING_PROJECT",
        "GRAFT_PROJECT",
        "GRAFT_PROD_PROJECT",
    ):
        monkeypatch.delenv(var, raising=False)

    exit_code = main(
        [
            "secops",
            "test",
            "rules/secops/custom/gcp_iam_service_account_key_create.yaml",
            "--require-staging",
        ]
    )
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Error" in captured.err or "require-staging" in captured.err


def test_cli_test_execution_all_passed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("GRAFT_SECOPS_STAGING_PROJECT", "test-proj")
    monkeypatch.setenv("GRAFT_SECOPS_STAGING_LOCATION", "us")
    monkeypatch.setenv("GRAFT_SECOPS_STAGING_INSTANCE_ID", "test-inst")

    with patch("graft.engines.secops.adapter.SecOpsReplayAdapter") as mock_adapter_cls:
        mock_adapter = MagicMock()
        mock_adapter.run_test_vector.return_value = ReplayResult(
            test_id="test_powershell_download_cradle",
            passed=True,
            message="Passed: 1 detection matched",
            matched_events_count=1,
        )
        mock_adapter_cls.return_value = mock_adapter

        exit_code = main(
            ["secops", "test", "rules/secops/custom/gcp_iam_service_account_key_create.yaml"]
        )
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "PASS" in captured.out


def test_cli_test_execution_assertion_failed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("GRAFT_SECOPS_STAGING_PROJECT", "test-proj")
    monkeypatch.setenv("GRAFT_SECOPS_STAGING_LOCATION", "us")
    monkeypatch.setenv("GRAFT_SECOPS_STAGING_INSTANCE_ID", "test-inst")

    with patch("graft.engines.secops.adapter.SecOpsReplayAdapter") as mock_adapter_cls:
        mock_adapter = MagicMock()
        mock_adapter.run_test_vector.return_value = ReplayResult(
            test_id="test_powershell_download_cradle",
            passed=False,
            message="Failed: expected 1, got 0",
            matched_events_count=0,
        )
        mock_adapter_cls.return_value = mock_adapter

        exit_code = main(
            ["secops", "test", "rules/secops/custom/gcp_iam_service_account_key_create.yaml"]
        )
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "FAIL" in captured.err or "FAIL" in captured.out


def test_cli_test_json_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("GRAFT_SECOPS_STAGING_PROJECT", "test-proj")
    monkeypatch.setenv("GRAFT_SECOPS_STAGING_LOCATION", "us")
    monkeypatch.setenv("GRAFT_SECOPS_STAGING_INSTANCE_ID", "test-inst")

    with patch("graft.engines.secops.adapter.SecOpsReplayAdapter") as mock_adapter_cls:
        mock_adapter = MagicMock()
        mock_adapter.run_test_vector.return_value = ReplayResult(
            test_id="test_powershell_download_cradle",
            passed=True,
            message="Passed",
            matched_events_count=1,
        )
        mock_adapter_cls.return_value = mock_adapter

        exit_code = main(
            [
                "--json",
                "secops",
                "test",
                "rules/secops/custom/gcp_iam_service_account_key_create.yaml",
            ]
        )
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["success"] is True
        assert len(data["results"]) >= 1


def test_cli_test_skips_when_pointing_to_prod_tenant(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Only PROD variables set; staging falls back to PROD
    monkeypatch.delenv("GRAFT_SECOPS_STAGING_PROJECT", raising=False)
    monkeypatch.delenv("GRAFT_STAGING_PROJECT", raising=False)
    monkeypatch.setenv("GRAFT_SECOPS_PROD_PROJECT", "prod-proj")
    monkeypatch.setenv("GRAFT_SECOPS_PROD_LOCATION", "us")
    monkeypatch.setenv("GRAFT_SECOPS_PROD_INSTANCE_ID", "prod-inst")

    exit_code = main(
        ["secops", "test", "rules/secops/custom/gcp_iam_service_account_key_create.yaml"]
    )
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "WARNING" in captured.out
    assert "cannot run against production" in captured.out


def test_cli_test_fails_when_pointing_to_prod_tenant_and_require_staging(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("GRAFT_SECOPS_STAGING_PROJECT", raising=False)
    monkeypatch.delenv("GRAFT_STAGING_PROJECT", raising=False)
    monkeypatch.setenv("GRAFT_SECOPS_PROD_PROJECT", "prod-proj")
    monkeypatch.setenv("GRAFT_SECOPS_PROD_LOCATION", "us")
    monkeypatch.setenv("GRAFT_SECOPS_PROD_INSTANCE_ID", "prod-inst")

    exit_code = main(
        [
            "secops",
            "test",
            "rules/secops/custom/gcp_iam_service_account_key_create.yaml",
            "--require-staging",
        ]
    )
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Error" in captured.err
