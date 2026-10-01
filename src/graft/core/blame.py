import shutil
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True)
class RuleGitMetadata:
    path: Path
    author: str
    created_at: str
    last_modified_at: str
    commit_count: int
    contributor_count: int


def _normalize_utc_date(raw_ts: str) -> str:
    cleaned = raw_ts.strip()
    if not cleaned:
        return "Unknown"
    try:
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is not None:
            dt = dt.astimezone(UTC)
        return dt.strftime("%Y-%m-%d")
    except ValueError:
        return cleaned[:10] if len(cleaned) >= 10 else "Unknown"


def extract_git_metadata(path: Path | str, cwd: Path | None = None) -> RuleGitMetadata:
    file_path = Path(path)
    git_bin = shutil.which("git") or "git"

    author = "Unknown"
    created_at = "Unknown"
    last_modified_at = "Unknown"
    commit_count = 0
    contributor_count = 0

    if cwd is not None:
        effective_cwd: Path | None = cwd
        target_arg = str(file_path)
    elif str(file_path.parent) not in ("", "."):
        effective_cwd = file_path.parent
        target_arg = file_path.name
    else:
        effective_cwd = None
        target_arg = str(file_path)

    try:
        proc = subprocess.run(  # noqa: S603
            [
                git_bin,
                "log",
                "--follow",
                "--format=%aI%x00%aN%x00%aE",
                "--",
                target_arg,
            ],
            cwd=effective_cwd,
            capture_output=True,
            text=True,
            check=False,
        )
        lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        if lines:
            records: list[tuple[str, str, str]] = []
            for line in lines:
                parts = line.split("\x00")
                iso_ts = parts[0].strip() if len(parts) > 0 else ""
                commit_author = parts[1].strip() if len(parts) > 1 else ""
                commit_email = parts[2].strip() if len(parts) > 2 else ""
                records.append((iso_ts, commit_author, commit_email))

            commit_count = len(records)
            last_modified_at = _normalize_utc_date(records[0][0])
            created_at = _normalize_utc_date(records[-1][0])
            if records[-1][1]:
                author = records[-1][1]
            emails = {rec[2].lower() for rec in records if rec[2]}
            contributor_count = len(emails)

    except (subprocess.SubprocessError, OSError):
        pass

    return RuleGitMetadata(
        path=file_path,
        author=author,
        created_at=created_at,
        last_modified_at=last_modified_at,
        commit_count=commit_count,
        contributor_count=contributor_count,
    )
