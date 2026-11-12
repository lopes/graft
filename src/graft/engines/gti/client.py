from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Any, cast

from graft.engines.gti.config import GTIConfig

logger = logging.getLogger("graft.gti.client")


class GTIApiError(RuntimeError):
    def __init__(
        self,
        message: str,
        status_code: int,
        error_code: str = "",
        method: str = "",
        path: str = "",
    ) -> None:
        code_part = f" ({error_code})" if error_code else ""
        endpoint_target = f"{method} {path}".strip()
        endpoint_part = f" on {endpoint_target}" if endpoint_target else ""
        super().__init__(f"GTI API Error {status_code}{code_part}{endpoint_part}: {message}")
        self.status_code = status_code
        self.error_code = error_code
        self.method = method
        self.path = path


class GTIClient:
    def __init__(
        self,
        config: GTIConfig,
        max_retries: int = 3,
        base_delay_seconds: float = 1.0,
        timeout_seconds: float = 30.0,
    ) -> None:
        self._config = config
        self._max_retries = max_retries
        self._base_delay_seconds = base_delay_seconds
        self._timeout_seconds = timeout_seconds
        self._cached_user_id: str | None = None

    @property
    def config(self) -> GTIConfig:
        return self._config

    def _resolve_url(
        self,
        path: str,
        params: Mapping[str, str] | None = None,
    ) -> str:
        if path.startswith("http://"):
            raise ValueError(f"Insecure cleartext HTTP URL rejected (HTTPS required): {path}")
        if path.startswith("https://"):
            url = path
        elif path.startswith("/"):
            url = f"{self._config.base_url}{path}"
        else:
            url = f"{self._config.base_url}/{path}"

        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https":
            raise ValueError(f"Invalid URL scheme (HTTPS required): {url}")

        if params:
            query_string = urllib.parse.urlencode(params)
            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}{query_string}"
        return url

    def get_current_user_id(self) -> str:
        if self._cached_user_id is not None:
            return self._cached_user_id
        payload = self.request("GET", f"/users/{self._config.api_key}")
        data = payload.get("data", {})
        if isinstance(data, dict) and data.get("id"):
            self._cached_user_id = str(data["id"])
            return self._cached_user_id
        raise GTIApiError(
            message="Unable to resolve authenticated GTI user ID",
            status_code=500,
            error_code="UserResolutionError",
            method="GET",
            path="/users/<self>",
        )

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        url = self._resolve_url(path, params=params)
        safe_path = (
            "/users/<self>"
            if path.startswith("/users/") and "/" not in path[len("/users/") :]
            else path.replace(self._config.api_key, "<self>")
        )
        headers: dict[str, str] = {
            "x-apikey": self._config.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        body_bytes = json.dumps(payload).encode("utf-8") if payload is not None else None

        attempt = 0
        while True:
            attempt += 1
            logger.debug("GTI API request: %s %s (attempt %d)", method, safe_path, attempt)
            req = urllib.request.Request(  # noqa: S310
                url, data=body_bytes, headers=headers, method=method
            )
            try:
                with urllib.request.urlopen(  # noqa: S310
                    req, timeout=self._timeout_seconds
                ) as resp:
                    raw_body = resp.read().decode("utf-8")
                    if not raw_body.strip():
                        return {}
                    parsed = json.loads(raw_body)
                    if isinstance(parsed, dict):
                        return cast("dict[str, Any]", parsed)
                    return {"data": parsed}
            except urllib.error.HTTPError as exc:
                status_code = exc.code
                raw_err = exc.read().decode("utf-8", errors="replace")

                if status_code in (429, 502, 503, 504) and attempt <= self._max_retries:
                    delay = self._base_delay_seconds * (2 ** (attempt - 1))
                    logger.warning(
                        "Transient HTTP %d from GTI API on %s %s; retrying in %.2fs (%d/%d)...",
                        status_code,
                        method,
                        safe_path,
                        delay,
                        attempt,
                        self._max_retries,
                    )
                    time.sleep(delay)
                    continue

                err_msg = raw_err or exc.reason
                err_code = ""
                try:
                    err_json = json.loads(raw_err)
                    if isinstance(err_json, dict) and isinstance(err_json.get("error"), dict):
                        err_obj = err_json["error"]
                        err_msg = str(err_obj.get("message", err_msg))
                        err_code = str(err_obj.get("code", ""))
                except json.JSONDecodeError:
                    pass

                raise GTIApiError(
                    message=err_msg,
                    status_code=status_code,
                    error_code=err_code,
                    method=method,
                    path=safe_path,
                ) from exc
            except urllib.error.URLError as exc:
                if attempt <= self._max_retries:
                    delay = self._base_delay_seconds * (2 ** (attempt - 1))
                    logger.warning(
                        "Transport error contacting GTI API (%s) on %s %s; "
                        "retrying in %.2fs (%d/%d)...",
                        exc.reason,
                        method,
                        safe_path,
                        delay,
                        attempt,
                        self._max_retries,
                    )
                    time.sleep(delay)
                    continue
                raise GTIApiError(
                    message=f"Network transport error: {exc.reason}",
                    status_code=0,
                    error_code="TransportError",
                    method=method,
                    path=safe_path,
                ) from exc

    def get(
        self,
        path: str,
        params: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        return self.request("GET", path, params=params)

    def post(
        self,
        path: str,
        payload: dict[str, Any],
        params: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        return self.request("POST", path, payload=payload, params=params)

    def patch(
        self,
        path: str,
        payload: dict[str, Any],
        params: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        return self.request("PATCH", path, payload=payload, params=params)

    def delete(
        self,
        path: str,
        params: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        return self.request("DELETE", path, params=params)
