import subprocess
from pathlib import Path
from unittest.mock import patch

from graft.core.git import get_changed_files


def test_get_changed_files_branch_diff(tmp_path: Path) -> None:
    def fake_subprocess_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        cmd_str = " ".join(cmd)
        if "origin/main...HEAD" in cmd_str:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout="rulesets/secops/custom/rule_a.yaml\nrulesets/secops/managed.yaml\n",
                stderr="",
            )
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_subprocess_run):
        changed = get_changed_files(cwd=tmp_path)

    expected = {
        (tmp_path / "rulesets/secops/custom/rule_a.yaml").resolve(),
        (tmp_path / "rulesets/secops/managed.yaml").resolve(),
    }
    assert changed == expected


def test_get_changed_files_fallback_to_main(tmp_path: Path) -> None:
    def fake_subprocess_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        cmd_str = " ".join(cmd)
        if "origin/main...HEAD" in cmd_str:
            return subprocess.CompletedProcess(args=cmd, returncode=128, stdout="", stderr="fatal")
        if "main...HEAD" in cmd_str:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout="rulesets/secops/custom/rule_b.yaml\n",
                stderr="",
            )
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_subprocess_run):
        changed = get_changed_files(cwd=tmp_path)

    assert (tmp_path / "rulesets/secops/custom/rule_b.yaml").resolve() in changed


def test_get_changed_files_includes_working_tree_and_untracked(tmp_path: Path) -> None:
    def fake_subprocess_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        cmd_str = " ".join(cmd)
        if "origin/main...HEAD" in cmd_str:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
        if "diff --name-only HEAD" in cmd_str:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout="rulesets/secops/custom/modified_unstaged.yaml\n",
                stderr="",
            )
        if "ls-files --others" in cmd_str:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout="rulesets/secops/custom/new_untracked.yaml\n",
                stderr="",
            )
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_subprocess_run):
        changed = get_changed_files(cwd=tmp_path)

    assert (tmp_path / "rulesets/secops/custom/modified_unstaged.yaml").resolve() in changed
    assert (tmp_path / "rulesets/secops/custom/new_untracked.yaml").resolve() in changed


def test_get_changed_files_git_error_returns_empty(tmp_path: Path) -> None:
    with patch(
        "subprocess.run",
        side_effect=subprocess.SubprocessError("git not installed or crashed"),
    ):
        changed = get_changed_files(cwd=tmp_path)

    assert changed == set()
