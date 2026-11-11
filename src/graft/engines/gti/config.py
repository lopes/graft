from __future__ import annotations

import os
import urllib.parse
from dataclasses import dataclass
from typing import Literal, Self

DEFAULT_GTI_BASE_URL = "https://www.virustotal.com/api/v3"
DEFAULT_GTI_FILTER = "tag:graft"


@dataclass(frozen=True)
class GTIConfig:
    api_key: str
    base_url: str = DEFAULT_GTI_BASE_URL
    ruleset_filter: str = DEFAULT_GTI_FILTER
    notification_emails: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        parsed = urllib.parse.urlsplit(self.base_url)
        if parsed.scheme != "https":
            raise ValueError(
                f"Insecure or invalid GTI base URL rejected (HTTPS required): {self.base_url}"
            )

    @classmethod
    def from_env(cls, target: Literal["staging", "prod"] = "staging") -> Self:
        tgt = target.upper()
        api_key = (
            os.environ.get(f"GRAFT_GTI_{tgt}_API_KEY")
            or os.environ.get("GRAFT_GTI_API_KEY")
            or (os.environ.get("GRAFT_GTI_PROD_API_KEY") if target == "staging" else None)
        )
        if not api_key:
            raise KeyError(
                f"Missing required GTI environment variable for target '{target}': "
                f"GRAFT_GTI_{tgt}_API_KEY (or GRAFT_GTI_API_KEY)"
            )

        base_url = (os.environ.get("GRAFT_GTI_BASE_URL") or DEFAULT_GTI_BASE_URL).rstrip("/")
        ruleset_filter = (os.environ.get("GRAFT_GTI_FILTER") or DEFAULT_GTI_FILTER).strip()

        raw_emails = os.environ.get("GRAFT_GTI_NOTIFICATION_EMAILS", "")
        emails = tuple(e.strip() for e in raw_emails.split(",") if e.strip())

        return cls(
            api_key=api_key.strip(),
            base_url=base_url,
            ruleset_filter=ruleset_filter,
            notification_emails=emails,
        )
