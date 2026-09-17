from pathlib import Path

import pytest

from graft.core.env import load_env_file


def test_load_env_file_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        """
# Comment line
GRAFT_PROJECT=test-lab-project
export GRAFT_LOCATION="us"
GRAFT_INSTANCE_ID='12345678-abcd-ef01-2345-6789abcdef01'
EMPTY_VAL=
# Another comment
    SPACED_KEY = "spaced_value"
""",
        encoding="utf-8",
    )

    monkeypatch.delenv("GRAFT_PROJECT", raising=False)
    monkeypatch.delenv("GRAFT_LOCATION", raising=False)
    monkeypatch.delenv("GRAFT_INSTANCE_ID", raising=False)
    monkeypatch.delenv("SPACED_KEY", raising=False)

    loaded = load_env_file(env_file)

    assert loaded["GRAFT_PROJECT"] == "test-lab-project"
    assert loaded["GRAFT_LOCATION"] == "us"
    assert loaded["GRAFT_INSTANCE_ID"] == "12345678-abcd-ef01-2345-6789abcdef01"
    assert loaded["SPACED_KEY"] == "spaced_value"


def test_load_env_file_does_not_overwrite_existing_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("EXISTING_KEY=from_file\n", encoding="utf-8")

    monkeypatch.setenv("EXISTING_KEY", "from_environment")
    loaded = load_env_file(env_file)

    assert "EXISTING_KEY" not in loaded
    import os

    assert os.environ["EXISTING_KEY"] == "from_environment"


def test_load_env_file_nonexistent_returns_empty() -> None:
    loaded = load_env_file(Path("/nonexistent/.env"))
    assert loaded == {}
