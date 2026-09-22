import subprocess
from pathlib import Path
from unittest.mock import patch

from graft.core.blame import extract_git_metadata


def test_extract_git_metadata_success(tmp_path: Path) -> None:
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text("dummy", encoding="utf-8")

    def fake_subprocess_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        cmd_str = " ".join(cmd)
        if "--diff-filter=A" in cmd_str:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="Alice Creator|2026-01-15T10:00:00Z\n", stderr=""
            )
        if "-n 1" in cmd_str:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="Bob Modifier|2026-09-17T12:00:00Z\n", stderr=""
            )
        if "rev-list --count" in cmd_str:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="5\n", stderr="")
        if "--format=%ae" in cmd_str:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="alice@example.com\nbob@example.com\n", stderr=""
            )
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_subprocess_run):
        meta = extract_git_metadata(rule_file)

    assert meta.author == "Alice Creator"
    assert meta.created_at == "2026-01-15T10:00:00Z"
    assert meta.last_modified_by == "Bob Modifier"
    assert meta.last_modified_at == "2026-09-17T12:00:00Z"
    assert meta.commit_count == 5
    assert meta.contributor_count == 2


def test_extract_git_metadata_uncommitted_fallback(tmp_path: Path) -> None:
    uncommitted = tmp_path / "uncommitted.yaml"
    uncommitted.write_text("dummy", encoding="utf-8")

    with patch(
        "subprocess.run",
        return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
    ):
        meta = extract_git_metadata(uncommitted)

    assert meta.author == "Unknown"
    assert meta.created_at == "Unknown"
    assert meta.last_modified_by == "Unknown"
    assert meta.last_modified_at == "Unknown"
    assert meta.commit_count == 0
    assert meta.contributor_count == 0


def test_extract_git_metadata_git_error_fallback(tmp_path: Path) -> None:
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text("dummy", encoding="utf-8")

    with patch(
        "subprocess.run",
        side_effect=subprocess.SubprocessError("git not found or error"),
    ):
        meta = extract_git_metadata(rule_file)

    assert meta.author == "Unknown"
    assert meta.created_at == "Unknown"
    assert meta.commit_count == 0


def test_extract_git_metadata_real_repo_on_committed_file() -> None:
    # Test on an actual tracked repository file
    meta = extract_git_metadata("GRAFT_MASTER_PLAN.md")
    assert meta.author != "Unknown"
    assert meta.created_at != "Unknown"
    assert meta.commit_count >= 1
