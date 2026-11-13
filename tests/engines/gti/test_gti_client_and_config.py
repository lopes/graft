from __future__ import annotations

import io
import json
import urllib.error
from email.message import Message
from typing import Any
from unittest.mock import patch

import pytest

from graft.engines.gti.client import GTIApiError, GTIClient
from graft.engines.gti.config import GTIConfig


def test_gti_config_from_env_single_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRAFT_GTI_STAGING_API_KEY", raising=False)
    monkeypatch.delenv("GRAFT_GTI_PROD_API_KEY", raising=False)
    monkeypatch.setenv("GRAFT_GTI_API_KEY", "SYNTHETIC_TEST_KEY_000000")
    monkeypatch.delenv("GRAFT_GTI_FILTER", raising=False)

    cfg = GTIConfig.from_env("prod")
    assert cfg.api_key == "SYNTHETIC_TEST_KEY_000000"
    assert cfg.base_url == "https://www.virustotal.com/api/v3"
    assert cfg.ruleset_filter == "owner:self"


def test_gti_config_from_env_tiered_isolates_staging_from_prod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GRAFT_GTI_API_KEY", raising=False)
    monkeypatch.delenv("GRAFT_GTI_STAGING_API_KEY", raising=False)
    monkeypatch.setenv("GRAFT_GTI_PROD_API_KEY", "SYNTHETIC_TEST_PROD_KEY_000000")
    monkeypatch.setenv("GRAFT_GTI_FILTER", "tag:team-ti")
    monkeypatch.setenv("GRAFT_GTI_NOTIFICATION_EMAILS", "soc@example.com, alerts@example.com")

    with pytest.raises(KeyError, match="GRAFT_GTI_STAGING_API_KEY"):
        GTIConfig.from_env("staging")

    prod_cfg = GTIConfig.from_env("prod")
    assert prod_cfg.api_key == "SYNTHETIC_TEST_PROD_KEY_000000"
    assert prod_cfg.ruleset_filter == "tag:team-ti"
    assert prod_cfg.notification_emails == ("soc@example.com", "alerts@example.com")

    monkeypatch.setenv("GRAFT_GTI_STAGING_API_KEY", "SYNTHETIC_TEST_STAGING_KEY_000000")
    staging_cfg = GTIConfig.from_env("staging")
    assert staging_cfg.api_key == "SYNTHETIC_TEST_STAGING_KEY_000000"


def test_gti_config_missing_key_raises_key_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GRAFT_GTI_API_KEY", raising=False)
    monkeypatch.delenv("GRAFT_GTI_STAGING_API_KEY", raising=False)
    monkeypatch.delenv("GRAFT_GTI_PROD_API_KEY", raising=False)

    with pytest.raises(KeyError, match="GRAFT_GTI"):
        GTIConfig.from_env("prod")


def test_gti_config_rejects_cleartext_http_base_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GRAFT_GTI_API_KEY", "SYNTHETIC_TEST_KEY_000000")
    monkeypatch.setenv("GRAFT_GTI_BASE_URL", "http://www.virustotal.com/api/v3")

    with pytest.raises(ValueError, match="HTTPS required"):
        GTIConfig.from_env("prod")


class _FakeResponse:
    def __init__(self, payload: dict[str, Any] | str, status: int = 200) -> None:
        raw = payload if isinstance(payload, str) else json.dumps(payload)
        self._bytes = raw.encode("utf-8")
        self.status = status

    def read(self) -> bytes:
        return self._bytes

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def test_gti_client_injects_apikey_and_caches_user_id() -> None:
    cfg = GTIConfig(api_key="SYNTHETIC_TEST_KEY_000000")
    client = GTIClient(cfg, base_delay_seconds=0.0)
    captured_requests: list[Any] = []

    def fake_urlopen(req: Any, timeout: float = 30.0) -> _FakeResponse:
        captured_requests.append(req)
        return _FakeResponse({"data": {"type": "user", "id": "synthetic_user_01"}})

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        uid1 = client.get_current_user_id()
        uid2 = client.get_current_user_id()

    assert uid1 == "synthetic_user_01"
    assert uid2 == "synthetic_user_01"
    assert len(captured_requests) == 1
    assert captured_requests[0].get_header("X-apikey") == "SYNTHETIC_TEST_KEY_000000"


def test_gti_client_rejects_http_url() -> None:
    cfg = GTIConfig(api_key="SYNTHETIC_TEST_KEY_000000")
    client = GTIClient(cfg)
    with pytest.raises(ValueError, match="HTTPS required"):
        client.get("http://www.virustotal.com/api/v3/intelligence/hunting_rulesets")


def test_gti_client_retries_on_429_and_parses_json_api_error() -> None:
    cfg = GTIConfig(api_key="SYNTHETIC_TEST_KEY_000000")
    client = GTIClient(cfg, max_retries=2, base_delay_seconds=0.0)
    calls = 0

    def fake_urlopen(req: Any, timeout: float = 30.0) -> _FakeResponse:
        nonlocal calls
        calls += 1
        if calls == 1:
            err_body = json.dumps(
                {"error": {"code": "QuotaExceededError", "message": "Rate limit"}}
            ).encode("utf-8")
            raise urllib.error.HTTPError(
                req.full_url, 429, "Too Many Requests", Message(), io.BytesIO(err_body)
            )
        return _FakeResponse({"data": []})

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        res = client.get("/intelligence/hunting_rulesets")

    assert res == {"data": []}
    assert calls == 2


def test_gti_client_raises_gti_api_error_on_400() -> None:
    cfg = GTIConfig(api_key="SYNTHETIC_TEST_KEY_000000")
    client = GTIClient(cfg, max_retries=1, base_delay_seconds=0.0)

    def fake_urlopen(req: Any, timeout: float = 30.0) -> _FakeResponse:
        err_body = json.dumps(
            {
                "error": {
                    "code": "InvalidArgumentError",
                    "message": "Invalid YARA rule: line 8: syntax error",
                }
            }
        ).encode("utf-8")
        raise urllib.error.HTTPError(
            req.full_url, 400, "Bad Request", Message(), io.BytesIO(err_body)
        )

    with (
        patch("urllib.request.urlopen", side_effect=fake_urlopen),
        pytest.raises(GTIApiError) as exc_info,
    ):
        client.post("/intelligence/hunting_rulesets", {"data": {}})

    assert exc_info.value.status_code == 400
    assert exc_info.value.error_code == "InvalidArgumentError"
    assert "line 8: syntax error" in str(exc_info.value)


def test_gti_client_redacts_api_key_in_user_resolution_error_path() -> None:
    cfg = GTIConfig(api_key="SYNTHETIC_TEST_KEY_000000")
    client = GTIClient(cfg, max_retries=0, base_delay_seconds=0.0)

    def fake_urlopen(req: Any, timeout: float = 30.0) -> _FakeResponse:
        err_body = json.dumps(
            {
                "error": {
                    "code": "NotAllowedError",
                    "message": (
                        "Invalid API key SYNTHETIC_TEST_KEY_000000 "
                        "on /users/SYNTHETIC_TEST_KEY_000000"
                    ),
                }
            }
        ).encode("utf-8")
        raise urllib.error.HTTPError(
            req.full_url, 401, "Unauthorized", Message(), io.BytesIO(err_body)
        )

    with (
        patch("urllib.request.urlopen", side_effect=fake_urlopen),
        pytest.raises(GTIApiError) as exc_info,
    ):
        client.get_current_user_id()

    assert exc_info.value.path == "/users/<self>"
    assert "SYNTHETIC_TEST_KEY_000000" not in str(exc_info.value)


def test_gti_config_and_client_reject_empty_netloc_cross_origin_and_unsafe_segments() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        GTIConfig(api_key="SYNTHETIC_TEST_KEY_000000", base_url="https:///api/v3")

    cfg = GTIConfig(api_key="SYNTHETIC_TEST_KEY_000000")
    client = GTIClient(cfg)

    with pytest.raises(ValueError, match="Cross-origin"):
        client.get("https://attacker.example.com/api/v3/intelligence/hunting_rulesets")

    bad_key_client = GTIClient(GTIConfig(api_key="bad/../../segment"))
    with pytest.raises(ValueError, match="Invalid GTI URL path segment"):
        bad_key_client.get_current_user_id()
