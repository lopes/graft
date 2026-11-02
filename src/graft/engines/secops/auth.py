import os
import subprocess

_GCLOUD_TIMEOUT_SECONDS = 15.0


class SecOpsAuthError(RuntimeError):
    pass


class SecOpsAuthResolver:
    def __init__(
        self,
        token: str | None = None,
        service_account_email: str | None = None,
    ) -> None:
        self._token = token
        self._service_account_email = service_account_email
        self._cached_gcloud_token: str | None = None

    def invalidate(self) -> None:
        self._cached_gcloud_token = None

    def get_token(self) -> str:
        if self._token:
            return self._token

        env_token = (
            os.environ.get("GRAFT_SECOPS_TOKEN")
            or os.environ.get("GRAFT_GCP_TOKEN")
            or os.environ.get("GRAFT_TOKEN")
        )
        if env_token:
            return env_token.strip()

        if self._cached_gcloud_token:
            return self._cached_gcloud_token

        cmd = ["gcloud", "auth", "print-access-token"]
        if self._service_account_email:
            cmd.append(f"--impersonate-service-account={self._service_account_email}")

        try:
            result = subprocess.run(  # noqa: S603  # nosemgrep
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=_GCLOUD_TIMEOUT_SECONDS,
            )
        except FileNotFoundError as err:
            raise SecOpsAuthError(
                "gcloud CLI not found. Install Google Cloud SDK or set GRAFT_SECOPS_TOKEN."
            ) from err
        except subprocess.TimeoutExpired as err:
            raise SecOpsAuthError(
                f"gcloud CLI timed out after {_GCLOUD_TIMEOUT_SECONDS:.0f}s "
                "while acquiring access token."
            ) from err

        if result.returncode != 0:
            raise SecOpsAuthError(
                f"Failed to acquire GCP access token via gcloud: {result.stderr.strip()}"
            )

        token = result.stdout.strip()
        if not token:
            raise SecOpsAuthError("gcloud returned an empty access token.")

        self._cached_gcloud_token = token
        return token

    def get_authorization_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.get_token()}"}
