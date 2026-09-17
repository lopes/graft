import os
from dataclasses import dataclass
from typing import Literal, Self


@dataclass(frozen=True)
class SecOpsConfig:
    project: str
    location: str
    instance_id: str
    service_account_email: str | None = None
    api_version: str = "v1"

    @property
    def base_url(self) -> str:
        return f"https://{self.location}-chronicle.googleapis.com/{self.api_version}"

    @property
    def instance_path(self) -> str:
        return f"projects/{self.project}/locations/{self.location}/instances/{self.instance_id}"

    def is_same_instance(self, other: "SecOpsConfig") -> bool:
        return (
            self.project == other.project
            and self.location == other.location
            and self.instance_id == other.instance_id
        )

    @classmethod
    def from_env(cls, target: Literal["staging", "prod"] = "staging") -> Self:
        tgt = target.upper()

        # 1. Engine-scoped targeted variables (e.g. GRAFT_SECOPS_STAGING_PROJECT)
        project = os.environ.get(f"GRAFT_SECOPS_{tgt}_PROJECT") or os.environ.get(
            f"GRAFT_{tgt}_PROJECT"
        )
        location = os.environ.get(f"GRAFT_SECOPS_{tgt}_LOCATION") or os.environ.get(
            f"GRAFT_{tgt}_LOCATION"
        )
        instance_id = os.environ.get(f"GRAFT_SECOPS_{tgt}_INSTANCE_ID") or os.environ.get(
            f"GRAFT_{tgt}_INSTANCE_ID"
        )
        sa_email = os.environ.get(f"GRAFT_SECOPS_{tgt}_SA_EMAIL") or os.environ.get(
            f"GRAFT_{tgt}_SA_EMAIL"
        )

        # 2. Engine-scoped lab / single-tenant fallback (e.g. GRAFT_SECOPS_PROJECT)
        if not project:
            project = os.environ.get("GRAFT_SECOPS_PROJECT") or os.environ.get("GRAFT_PROJECT")
            location = (
                location
                or os.environ.get("GRAFT_SECOPS_LOCATION")
                or os.environ.get("GRAFT_LOCATION")
            )
            instance_id = (
                instance_id
                or os.environ.get("GRAFT_SECOPS_INSTANCE_ID")
                or os.environ.get("GRAFT_INSTANCE_ID")
            )
            sa_email = (
                sa_email
                or os.environ.get("GRAFT_SECOPS_SA_EMAIL")
                or os.environ.get("GRAFT_SA_EMAIL")
            )

        # 3. Staging fallback to production coordinates when staging is not separated
        if not project and target == "staging":
            project = os.environ.get("GRAFT_SECOPS_PROD_PROJECT") or os.environ.get(
                "GRAFT_PROD_PROJECT"
            )
            location = (
                location
                or os.environ.get("GRAFT_SECOPS_PROD_LOCATION")
                or os.environ.get("GRAFT_PROD_LOCATION")
            )
            instance_id = (
                instance_id
                or os.environ.get("GRAFT_SECOPS_PROD_INSTANCE_ID")
                or os.environ.get("GRAFT_PROD_INSTANCE_ID")
            )
            sa_email = (
                sa_email
                or os.environ.get("GRAFT_SECOPS_PROD_SA_EMAIL")
                or os.environ.get("GRAFT_PROD_SA_EMAIL")
            )

        missing: list[str] = []
        if not project:
            missing.append(f"GRAFT_SECOPS_{tgt}_PROJECT (or GRAFT_SECOPS_PROJECT)")
        if not location:
            missing.append(f"GRAFT_SECOPS_{tgt}_LOCATION (or GRAFT_SECOPS_LOCATION)")
        if not instance_id:
            missing.append(f"GRAFT_SECOPS_{tgt}_INSTANCE_ID (or GRAFT_SECOPS_INSTANCE_ID)")

        if not project or not location or not instance_id:
            raise KeyError(
                f"Missing required SecOps environment variables for target '{target}': "
                f"{', '.join(missing)}"
            )

        return cls(
            project=project,
            location=location,
            instance_id=instance_id,
            service_account_email=sa_email,
        )
