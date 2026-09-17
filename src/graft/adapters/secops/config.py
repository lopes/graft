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

    @classmethod
    def from_env(cls, target: Literal["staging", "prod"] = "staging") -> Self:
        prefix = f"GRAFT_{target.upper()}_"
        project_key = f"{prefix}PROJECT"
        location_key = f"{prefix}LOCATION"
        instance_key = f"{prefix}INSTANCE_ID"
        sa_key = f"{prefix}SA_EMAIL"

        if project_key not in os.environ:
            raise KeyError(f"Missing required environment variable: {project_key}")
        if location_key not in os.environ:
            raise KeyError(f"Missing required environment variable: {location_key}")
        if instance_key not in os.environ:
            raise KeyError(f"Missing required environment variable: {instance_key}")

        return cls(
            project=os.environ[project_key],
            location=os.environ[location_key],
            instance_id=os.environ[instance_key],
            service_account_email=os.environ.get(sa_key),
        )
