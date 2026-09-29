import io
import json
import logging
import urllib.error
import urllib.request
from typing import Any

import pytest

from graft.engines.secops.auth import SecOpsAuthResolver
from graft.engines.secops.client import SecOpsApiError, SecOpsClient
from graft.engines.secops.config import SecOpsConfig


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
    assert exc_info.value.status == "INVALID_ARGUMENT"
    assert exc_info.value.method == "POST"
    assert exc_info.value.path == ":verifyRuleText"
    assert str(exc_info.value) == (
        "SecOps API Error 400 (INVALID_ARGUMENT) on POST :verifyRuleText: "
        "Invalid rule syntax at line 5"
    )


def test_client_retry_on_429_then_success(
    secops_config: SecOpsConfig,
    auth_resolver: SecOpsAuthResolver,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
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
    with caplog.at_level(logging.WARNING, logger="graft.secops.client"):
        result = client.request("GET", "rules")

    assert result == {"status": "ok"}
    assert calls == 2
    assert len(sleep_calls) == 1
    assert any(
        "SecOps API returned HTTP 429 on GET rules; retrying in 1.0s (attempt 1/2)" in r.message
        for r in caplog.records
    )


def test_client_retry_on_502_and_504_then_success(
    secops_config: SecOpsConfig,
    auth_resolver: SecOpsAuthResolver,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
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
                code=502,
                msg="Bad Gateway",
                hdrs=None,  # type: ignore[arg-type]
                fp=io.BytesIO(b""),
            )
        if calls == 2:
            raise urllib.error.HTTPError(
                url=req.full_url,
                code=504,
                msg="Gateway Timeout",
                hdrs=None,  # type: ignore[arg-type]
                fp=io.BytesIO(b""),
            )
        return MockSuccessResponse()

    sleep_calls: list[float] = []
    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)
    monkeypatch.setattr("time.sleep", lambda s: sleep_calls.append(s))

    client = SecOpsClient(config=secops_config, auth_resolver=auth_resolver, max_retries=2)
    with caplog.at_level(logging.WARNING, logger="graft.secops.client"):
        result = client.request("GET", "findingsRefinements")

    assert result == {"status": "ok"}
    assert calls == 3
    assert sleep_calls == [1.0, 2.0]
    assert any(
        "SecOps API returned HTTP 502 on GET findingsRefinements; retrying in 1.0s (attempt 1/2)"
        in r.message
        for r in caplog.records
    )
    assert any(
        "SecOps API returned HTTP 504 on GET findingsRefinements; retrying in 2.0s (attempt 2/2)"
        in r.message
        for r in caplog.records
    )


def test_client_retry_on_timeout_then_success(
    secops_config: SecOpsConfig,
    auth_resolver: SecOpsAuthResolver,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    calls = 0

    class MockSuccessResponse:
        def __init__(self) -> None:
            self.status = 200

        def read(self) -> bytes:
            return b'{"findingsRefinements": []}'

        def __enter__(self) -> "MockSuccessResponse":
            return self

        def __exit__(self, *args: object) -> None:
            pass

    def mock_urlopen(req: urllib.request.Request, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TimeoutError("The read operation timed out")
        return MockSuccessResponse()

    sleep_calls: list[float] = []
    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)
    monkeypatch.setattr("time.sleep", lambda s: sleep_calls.append(s))

    client = SecOpsClient(config=secops_config, auth_resolver=auth_resolver, max_retries=2)
    with caplog.at_level(logging.WARNING, logger="graft.secops.client"):
        result = client.request("GET", "findingsRefinements")

    assert result == {"findingsRefinements": []}
    assert calls == 2
    assert sleep_calls == [1.0]
    assert any(
        "SecOps API transport error on GET findingsRefinements "
        "(The read operation timed out); retrying in 1.0s (attempt 1/2)" in r.message
        for r in caplog.records
    )


def test_client_network_urlerror_wrapped_in_secops_api_error(
    secops_config: SecOpsConfig, auth_resolver: SecOpsAuthResolver, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = 0

    def mock_urlopen(req: urllib.request.Request, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        raise urllib.error.URLError("Temporary failure in name resolution")

    sleep_calls: list[float] = []
    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)
    monkeypatch.setattr("time.sleep", lambda s: sleep_calls.append(s))

    client = SecOpsClient(config=secops_config, auth_resolver=auth_resolver, max_retries=2)
    with pytest.raises(SecOpsApiError) as exc_info:
        client.request("GET", "rules")

    assert calls == 3
    assert sleep_calls == [1.0, 2.0]
    assert str(exc_info.value) == (
        "SecOps API Error 0 (UNAVAILABLE) on GET rules: "
        "Network transport error: Temporary failure in name resolution"
    )
    assert exc_info.value.status_code == 0
    assert exc_info.value.method == "GET"
    assert exc_info.value.path == "rules"


def test_client_timeout_error_wrapped_in_secops_api_error(
    secops_config: SecOpsConfig, auth_resolver: SecOpsAuthResolver, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = 0

    def mock_urlopen(req: urllib.request.Request, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        raise TimeoutError("The read operation timed out")

    sleep_calls: list[float] = []
    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)
    monkeypatch.setattr("time.sleep", lambda s: sleep_calls.append(s))

    client = SecOpsClient(config=secops_config, auth_resolver=auth_resolver, max_retries=2)
    with pytest.raises(SecOpsApiError) as exc_info:
        client.request("GET", "rules")

    assert calls == 3
    assert sleep_calls == [1.0, 2.0]
    assert str(exc_info.value) == (
        "SecOps API Error 504 (UNAVAILABLE) on GET rules: "
        "Network transport error: The read operation timed out"
    )
    assert exc_info.value.status_code == 504
    assert exc_info.value.method == "GET"
    assert exc_info.value.path == "rules"


def test_secops_api_error_formatting_variants() -> None:
    err_minimal = SecOpsApiError("Not found", 404)
    assert str(err_minimal) == "SecOps API Error 404: Not found"

    err_status_only = SecOpsApiError("Forbidden", 403, status="PERMISSION_DENIED")
    assert str(err_status_only) == "SecOps API Error 403 (PERMISSION_DENIED): Forbidden"

    err_endpoint_only = SecOpsApiError("Bad gateway", 502, method="POST", path="rules")
    assert str(err_endpoint_only) == "SecOps API Error 502 on POST rules: Bad gateway"

    err_full = SecOpsApiError(
        "Invalid query",
        400,
        status="INVALID_ARGUMENT",
        method="POST",
        path="findingsRefinements",
    )
    assert (
        str(err_full)
        == "SecOps API Error 400 (INVALID_ARGUMENT) on POST findingsRefinements: Invalid query"
    )
