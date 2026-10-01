import subprocess
from pathlib import Path
from unittest.mock import patch

from graft.core.blame import extract_git_metadata


def test_extract_git_metadata_success(tmp_path: Path) -> None:
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text("dummy", encoding="utf-8")

    calls: list[tuple[list[str], object]] = []

    def fake_subprocess_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((cmd, kwargs.get("cwd")))
        stdout = "\n".join(
            [
                "2026-09-17T12:00:00Z\x00Bob Jones\x00bob@example.com",
                "2026-05-10T08:00:00+02:00\x00Alice Smith\x00Alice@Example.com",
                "2026-01-15T23:30:00-03:00\x00Alice Smith\x00alice@example.com",
            ]
        )
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=stdout + "\n", stderr="")

    with patch("subprocess.run", side_effect=fake_subprocess_run):
        meta = extract_git_metadata(rule_file)

    assert len(calls) == 1
    cmd_args, call_cwd = calls[0]
    assert "--follow" in cmd_args
    assert call_cwd == tmp_path
    assert cmd_args[-1] == "rule.yaml"
    assert meta.author == "Alice Smith"
    assert meta.created_at == "2026-01-16"
    assert meta.last_modified_at == "2026-09-17"
    assert meta.commit_count == 3
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
    assert meta.last_modified_at == "Unknown"
    assert meta.commit_count == 0
    assert meta.contributor_count == 0


def test_extract_git_metadata_real_repo_on_committed_file() -> None:
    meta = extract_git_metadata("README.md")
    assert meta.author != "Unknown"
    assert len(meta.created_at) == 10
    assert meta.created_at[4] == "-" and meta.created_at[7] == "-"
    assert len(meta.last_modified_at) == 10
    assert meta.last_modified_at[4] == "-" and meta.last_modified_at[7] == "-"
    assert meta.commit_count >= 1
    assert meta.contributor_count >= 1
