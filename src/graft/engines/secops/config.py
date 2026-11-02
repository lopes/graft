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
    def _read_tier(
        cls,
        prefixes: tuple[str, ...],
    ) -> tuple[str | None, str | None, str | None, str | None]:
        def _first(suffix: str) -> str | None:
            for prefix in prefixes:
                val = os.environ.get(f"{prefix}{suffix}")
                if val:
                    return val
            return None

        return (
            _first("PROJECT"),
            _first("LOCATION"),
            _first("INSTANCE_ID"),
            _first("SA_EMAIL"),
        )

    @classmethod
    def from_env(cls, target: Literal["staging", "prod"] = "staging") -> Self:
        tgt = target.upper()

        # 1. Engine-scoped targeted variables (e.g. GRAFT_SECOPS_STAGING_PROJECT)
        project, location, instance_id, sa_email = cls._read_tier(
            (f"GRAFT_SECOPS_{tgt}_", f"GRAFT_{tgt}_")
        )

        # 2. Engine-scoped lab / single-tenant fallback (e.g. GRAFT_SECOPS_PROJECT)
        if not project:
            project, location, instance_id, sa_email = cls._read_tier(("GRAFT_SECOPS_", "GRAFT_"))

        # 3. Staging fallback to production coordinates when staging is not separated
        if not project and target == "staging":
            project, location, instance_id, sa_email = cls._read_tier(
                ("GRAFT_SECOPS_PROD_", "GRAFT_PROD_")
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
