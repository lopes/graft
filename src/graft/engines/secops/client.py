import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Any, cast

from graft.engines.secops.auth import SecOpsAuthResolver
from graft.engines.secops.config import SecOpsConfig

logger = logging.getLogger("graft.secops.client")


class SecOpsApiError(RuntimeError):
    def __init__(
        self,
        message: str,
        status_code: int,
        status: str = "",
        details: list[dict[str, object]] | None = None,
        method: str = "",
        path: str = "",
    ) -> None:
        status_part = f" ({status})" if status else ""
        endpoint_target = f"{method} {path}".strip()
        endpoint_part = f" on {endpoint_target}" if endpoint_target else ""
        super().__init__(f"SecOps API Error {status_code}{status_part}{endpoint_part}: {message}")
        self.status_code = status_code
        self.status = status
        self.details = details or []
        self.method = method
        self.path = path


class SecOpsClient:
    def __init__(
        self,
        config: SecOpsConfig,
        auth_resolver: SecOpsAuthResolver | None = None,
        max_retries: int = 3,
        base_delay_seconds: float = 1.0,
        timeout_seconds: float = 30.0,
    ) -> None:
        self._config = config
        self._auth_resolver = auth_resolver or SecOpsAuthResolver(
            service_account_email=config.service_account_email
        )
        self._max_retries = max_retries
        self._base_delay_seconds = base_delay_seconds
        self._timeout_seconds = timeout_seconds

    def _resolve_url(
        self,
        path: str,
        params: Mapping[str, str] | None = None,
        api_version: str | None = None,
    ) -> str:
        base_url = (
            f"https://{self._config.location}-chronicle.googleapis.com/{api_version}"
            if api_version
            else self._config.base_url
        )
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        elif path.startswith(":"):
            url = f"{base_url}/{self._config.instance_path}{path}"
        elif path.startswith("/"):
            url = f"{base_url}{path}"
        elif path.startswith("projects/"):
            url = f"{base_url}/{path}"
        else:
            url = f"{base_url}/{self._config.instance_path}/{path}"

        if params:
            query = urllib.parse.urlencode(dict(params))
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{query}"

        return url

    def request(
        self,
        method: str,
        path: str,
        body: Mapping[str, object] | None = None,
        params: Mapping[str, str] | None = None,
        api_version: str | None = None,
    ) -> dict[str, object]:
        http_method = method.upper()
        url = self._resolve_url(path, params, api_version=api_version)
        if not (url.startswith("https://") or url.startswith("http://")):
            raise ValueError(f"Invalid URL scheme: {url}")

        headers = {
            "Accept": "application/json",
            **self._auth_resolver.get_authorization_header(),
        }

        data: bytes | None = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(  # noqa: S310
            url=url,
            data=data,
            headers=headers,
            method=http_method,
        )

        attempts = 0
        while True:
            try:
                with urllib.request.urlopen(req, timeout=self._timeout_seconds) as response:  # noqa: S310
                    raw = response.read()
                    if not raw:
                        return {}
                    return cast(dict[str, object], json.loads(raw.decode("utf-8")))
            except urllib.error.HTTPError as err:
                status_code = err.code
                if status_code in (429, 502, 503, 504) and attempts < self._max_retries:
                    attempts += 1
                    sleep_time = self._base_delay_seconds * (2 ** (attempts - 1))
                    logger.warning(
                        "SecOps API returned HTTP %d on %s %s; retrying in %.1fs (attempt %d/%d)",
                        status_code,
                        http_method,
                        path,
                        sleep_time,
                        attempts,
                        self._max_retries,
                    )
                    time.sleep(sleep_time)
                    continue

                error_msg = err.reason
                error_status = ""
                error_details: list[dict[str, object]] = []

                try:
                    payload_raw = err.read()
                    if payload_raw:
                        error_json: dict[str, Any] = json.loads(payload_raw.decode("utf-8"))
                        if "error" in error_json and isinstance(error_json["error"], dict):
                            error_info = error_json["error"]
                            error_msg = error_info.get("message", error_msg)
                            error_status = error_info.get("status", "")
                            error_details = error_info.get("details", [])
                except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                    pass

                raise SecOpsApiError(
                    message=str(error_msg),
                    status_code=status_code,
                    status=error_status,
                    details=error_details,
                    method=http_method,
                    path=path,
                ) from err
            except (urllib.error.URLError, TimeoutError, OSError) as err:
                error_msg = getattr(err, "reason", str(err))
                if attempts < self._max_retries:
                    attempts += 1
                    sleep_time = self._base_delay_seconds * (2 ** (attempts - 1))
                    logger.warning(
                        "SecOps API transport error on %s %s (%s); "
                        "retrying in %.1fs (attempt %d/%d)",
                        http_method,
                        path,
                        error_msg,
                        sleep_time,
                        attempts,
                        self._max_retries,
                    )
                    time.sleep(sleep_time)
                    continue
                status_code = 504 if isinstance(err, TimeoutError) else 0
                raise SecOpsApiError(
                    message=f"Network transport error: {error_msg}",
                    status_code=status_code,
                    status="UNAVAILABLE",
                    method=http_method,
                    path=path,
                ) from err
