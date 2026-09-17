import io
import json
import urllib.error
import urllib.request
from typing import Any

import pytest

from graft.adapters.secops.auth import SecOpsAuthResolver
from graft.adapters.secops.client import SecOpsApiError, SecOpsClient
from graft.adapters.secops.config import SecOpsConfig


@pytest.fixture
def secops_config() -> SecOpsConfig:
    return SecOpsConfig(
        project="test-proj",
        location="us",
        instance_id="11111111-2222-3333-4444-555555555555",
    )


@pytest.fixture
def auth_resolver() -> SecOpsAuthResolver:
    bearer = "dummy-credential-value"
    return SecOpsAuthResolver(token=bearer)


def test_client_successful_get_request(
    secops_config: SecOpsConfig, auth_resolver: SecOpsAuthResolver, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected_response = {"rules": [{"name": "rule-1"}]}
    response_bytes = json.dumps(expected_response).encode("utf-8")

    class MockResponse:
        def __init__(self) -> None:
            self.status = 200

        def read(self) -> bytes:
            return response_bytes

        def __enter__(self) -> "MockResponse":
            return self

        def __exit__(self, *args: object) -> None:
            pass

    recorded_request: list[urllib.request.Request] = []

    def mock_urlopen(req: urllib.request.Request, **kwargs: Any) -> MockResponse:
        recorded_request.append(req)
        return MockResponse()

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    client = SecOpsClient(config=secops_config, auth_resolver=auth_resolver)
    result = client.request("GET", "rules")

    assert result == expected_response
    assert len(recorded_request) == 1
    req = recorded_request[0]
    assert (
        req.full_url
        == "https://us-chronicle.googleapis.com/v1/projects/test-proj/locations/us/instances/11111111-2222-3333-4444-555555555555/rules"
    )
    assert req.headers["Authorization"] == "Bearer dummy-credential-value"
    assert req.headers["Accept"] == "application/json"


def test_client_successful_post_request_with_colon_action(
    secops_config: SecOpsConfig, auth_resolver: SecOpsAuthResolver, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected_response = {"success": True}
    response_bytes = json.dumps(expected_response).encode("utf-8")

    class MockResponse:
        def __init__(self) -> None:
            self.status = 200

        def read(self) -> bytes:
            return response_bytes

        def __enter__(self) -> "MockResponse":
            return self

        def __exit__(self, *args: object) -> None:
            pass

    recorded_request: list[urllib.request.Request] = []

    def mock_urlopen(req: urllib.request.Request, **kwargs: Any) -> MockResponse:
        recorded_request.append(req)
        return MockResponse()

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    client = SecOpsClient(config=secops_config, auth_resolver=auth_resolver)
    payload = {"ruleText": "rule test { condition: true }"}
    result = client.request("POST", ":verifyRuleText", body=payload)

    assert result == expected_response
    assert len(recorded_request) == 1
    req = recorded_request[0]
    assert (
        req.full_url
        == "https://us-chronicle.googleapis.com/v1/projects/test-proj/locations/us/instances/11111111-2222-3333-4444-555555555555:verifyRuleText"
    )
    assert req.headers["Content-type"] == "application/json"
    assert req.data == json.dumps(payload).encode("utf-8")


def test_client_http_error_parsing(
    secops_config: SecOpsConfig, auth_resolver: SecOpsAuthResolver, monkeypatch: pytest.MonkeyPatch
) -> None:
    error_payload = {
        "error": {
            "code": 400,
            "message": "Invalid rule syntax at line 5",
            "status": "INVALID_ARGUMENT",
        }
    }
    error_bytes = json.dumps(error_payload).encode("utf-8")

    def mock_urlopen(req: urllib.request.Request, **kwargs: Any) -> Any:
        raise urllib.error.HTTPError(
            url=req.full_url,
            code=400,
            msg="Bad Request",
            hdrs=None,  # type: ignore[arg-type]
            fp=io.BytesIO(error_bytes),
        )

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    client = SecOpsClient(config=secops_config, auth_resolver=auth_resolver)
    with pytest.raises(SecOpsApiError) as exc_info:
        client.request("POST", ":verifyRuleText", body={"ruleText": "invalid"})

    assert exc_info.value.status_code == 400
    assert "Invalid rule syntax at line 5" in str(exc_info.value)
    assert exc_info.value.status == "INVALID_ARGUMENT"


def test_client_retry_on_429_then_success(
    secops_config: SecOpsConfig, auth_resolver: SecOpsAuthResolver, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = 0

    class MockSuccessResponse:
        def __init__(self) -> None:
            self.status = 200

        def read(self) -> bytes:
            return b'{"status": "ok"}'

        def __enter__(self) -> "MockSuccessResponse":
            return self

        def __exit__(self, *args: object) -> None:
            pass

    def mock_urlopen(req: urllib.request.Request, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise urllib.error.HTTPError(
                url=req.full_url,
                code=429,
                msg="Too Many Requests",
                hdrs=None,  # type: ignore[arg-type]
                fp=io.BytesIO(b'{"error": {"code": 429, "message": "Rate limit exceeded"}}'),
            )
        return MockSuccessResponse()

    sleep_calls: list[float] = []
    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)
    monkeypatch.setattr("time.sleep", lambda s: sleep_calls.append(s))

    client = SecOpsClient(config=secops_config, auth_resolver=auth_resolver, max_retries=2)
    result = client.request("GET", "rules")

    assert result == {"status": "ok"}
    assert calls == 2
    assert len(sleep_calls) == 1
