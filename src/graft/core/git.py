from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger("graft.core.git")


def get_changed_files(base_ref: str | None = None, cwd: Path | None = None) -> set[Path]:
    effective_cwd = cwd if cwd is not None else Path.cwd()
    git_bin = shutil.which("git") or "git"
    changed_paths: set[Path] = set()

    def _run_git(args: list[str]) -> list[str]:
        try:
            proc = subprocess.run(  # noqa: S603
                [git_bin, *args],
                cwd=effective_cwd,
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode == 0:
                return [line.strip() for line in proc.stdout.splitlines() if line.strip()]
            return []
        except subprocess.SubprocessError as exc:
            logger.debug("Git command failed %s: %s", args, exc)
            return []

    # 1. Branch diff against base
    candidates = [base_ref] if base_ref else ["origin/main...HEAD", "main...HEAD", "HEAD~1...HEAD"]
    branch_files: list[str] = []
    for target in candidates:
        if not target:
            continue
        branch_files = _run_git(["diff", "--name-only", target])
        if branch_files:
            break

    for f in branch_files:
        changed_paths.add((effective_cwd / f).resolve())

    # 2. Uncommitted tracked changes
    for f in _run_git(["diff", "--name-only", "HEAD"]):
        changed_paths.add((effective_cwd / f).resolve())

    # 3. Untracked files
    for f in _run_git(["ls-files", "--others", "--exclude-standard"]):
        changed_paths.add((effective_cwd / f).resolve())

    return changed_paths
