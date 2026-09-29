import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RuleGitMetadata:
    path: Path
    created_at: str
    last_modified_at: str
    commit_count: int
    contributor_count: int


def extract_git_metadata(path: Path | str, cwd: Path | None = None) -> RuleGitMetadata:
    file_path = Path(path)
    git_bin = shutil.which("git") or "git"

    created_at = "Unknown"
    last_modified_at = "Unknown"
    commit_count = 0
    contributor_count = 0

    try:
        creation_proc = subprocess.run(  # noqa: S603
            [
                git_bin,
                "log",
                "--diff-filter=A",
                "--follow",
                "--format=%aI",
                "-n",
                "1",
                "--",
                str(file_path),
            ],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
        out_creation = creation_proc.stdout.strip()
        if not out_creation:
            fallback_proc = subprocess.run(  # noqa: S603
                [
                    git_bin,
                    "log",
                    "--reverse",
                    "--format=%aI",
                    "--",
                    str(file_path),
                ],
                cwd=cwd,
                capture_output=True,
                text=True,
                check=False,
            )
            lines = fallback_proc.stdout.strip().splitlines()
            if lines:
                out_creation = lines[0]

        if out_creation:
            created_at = out_creation

        last_proc = subprocess.run(  # noqa: S603
            [
                git_bin,
                "log",
                "-n",
                "1",
                "--format=%aI",
                "--",
                str(file_path),
            ],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
        out_last = last_proc.stdout.strip()
        if out_last:
            last_modified_at = out_last

        count_proc = subprocess.run(  # noqa: S603
            [
                git_bin,
                "rev-list",
                "--count",
                "HEAD",
                "--",
                str(file_path),
            ],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
        count_str = count_proc.stdout.strip()
        if count_str.isdigit():
            commit_count = int(count_str)

        authors_proc = subprocess.run(  # noqa: S603
            [
                git_bin,
                "log",
                "--format=%ae",
                "--",
                str(file_path),
            ],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
        emails = {line.strip() for line in authors_proc.stdout.splitlines() if line.strip()}
        contributor_count = len(emails)

    except (subprocess.SubprocessError, OSError):
        pass

    return RuleGitMetadata(
        path=file_path,
        created_at=created_at,
        last_modified_at=last_modified_at,
        commit_count=commit_count,
        contributor_count=contributor_count,
    )
