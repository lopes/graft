import os
import subprocess


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

    def get_token(self) -> str:
        if self._token:
            return self._token

        env_token = os.environ.get("GRAFT_TOKEN")
        if env_token:
            return env_token.strip()

        cmd = ["gcloud", "auth", "print-access-token"]
        if self._service_account_email:
            cmd.append(f"--impersonate-service-account={self._service_account_email}")

        try:
            result = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError as err:
            raise SecOpsAuthError(
                "gcloud CLI not found. Install Google Cloud SDK or set GRAFT_TOKEN."
            ) from err

        if result.returncode != 0:
            raise SecOpsAuthError(
                f"Failed to acquire GCP access token via gcloud: {result.stderr.strip()}"
            )

        token = result.stdout.strip()
        if not token:
            raise SecOpsAuthError("gcloud returned an empty access token.")

        return token

    def get_authorization_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.get_token()}"}
