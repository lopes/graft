import subprocess
from unittest.mock import MagicMock

import pytest

from graft.adapters.secops.auth import SecOpsAuthError, SecOpsAuthResolver


def test_auth_resolver_explicit_token() -> None:
    resolver = SecOpsAuthResolver(token="explicit-token-abc")
    assert resolver.get_token() == "explicit-token-abc"
    assert resolver.get_authorization_header() == {"Authorization": "Bearer explicit-token-abc"}


def test_auth_resolver_env_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRAFT_TOKEN", "env-token-xyz")
    resolver = SecOpsAuthResolver()
    assert resolver.get_token() == "env-token-xyz"


def test_auth_resolver_gcloud_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRAFT_TOKEN", raising=False)

    mock_run = MagicMock(
        return_value=subprocess.CompletedProcess(
            args=["gcloud", "auth", "print-access-token"],
            returncode=0,
            stdout="gcloud-token-123\n",
            stderr="",
        )
    )
    monkeypatch.setattr(subprocess, "run", mock_run)

    resolver = SecOpsAuthResolver()
    token = resolver.get_token()

    assert token == "gcloud-token-123"
    mock_run.assert_called_once_with(
        ["gcloud", "auth", "print-access-token"],
        capture_output=True,
        text=True,
        check=False,
    )


def test_auth_resolver_gcloud_impersonation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRAFT_TOKEN", raising=False)

    mock_run = MagicMock(
        return_value=subprocess.CompletedProcess(
            args=[
                "gcloud",
                "auth",
                "print-access-token",
                "--impersonate-service-account=sa@proj.iam.gserviceaccount.com",
            ],
            returncode=0,
            stdout="impersonated-token-456\n",
            stderr="",
        )
    )
    monkeypatch.setattr(subprocess, "run", mock_run)

    resolver = SecOpsAuthResolver(service_account_email="sa@proj.iam.gserviceaccount.com")
    token = resolver.get_token()

    assert token == "impersonated-token-456"
    mock_run.assert_called_once_with(
        [
            "gcloud",
            "auth",
            "print-access-token",
            "--impersonate-service-account=sa@proj.iam.gserviceaccount.com",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_auth_resolver_gcloud_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRAFT_TOKEN", raising=False)

    mock_run = MagicMock(
        return_value=subprocess.CompletedProcess(
            args=["gcloud", "auth", "print-access-token"],
            returncode=1,
            stdout="",
            stderr="ERROR: (gcloud.auth.print-access-token) There are no credentials.\n",
        )
    )
    monkeypatch.setattr(subprocess, "run", mock_run)

    resolver = SecOpsAuthResolver()
    with pytest.raises(SecOpsAuthError, match="Failed to acquire GCP access token"):
        resolver.get_token()


def test_auth_resolver_gcloud_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRAFT_TOKEN", raising=False)

    def mock_raise(*args: object, **kwargs: object) -> None:
        raise FileNotFoundError("No such file or directory: 'gcloud'")

    monkeypatch.setattr(subprocess, "run", mock_raise)

    resolver = SecOpsAuthResolver()
    with pytest.raises(SecOpsAuthError, match="gcloud CLI not found"):
        resolver.get_token()
