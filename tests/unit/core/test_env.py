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

    try:
        loaded = load_env_file(env_file)

        assert loaded["GRAFT_PROJECT"] == "test-lab-project"
        assert loaded["GRAFT_LOCATION"] == "us"
        assert loaded["GRAFT_INSTANCE_ID"] == "12345678-abcd-ef01-2345-6789abcdef01"
        assert loaded["SPACED_KEY"] == "spaced_value"
    finally:
        import os

        for key in ("GRAFT_PROJECT", "GRAFT_LOCATION", "GRAFT_INSTANCE_ID", "SPACED_KEY"):
            os.environ.pop(key, None)


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


def test_load_env_file_loads_root_and_engine_env_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    monkeypatch.chdir(tmp_path)
    root_env = tmp_path / ".env"
    root_env.write_text(
        "GRAFT_LOG_LEVEL=DEBUG\nSHARED_KEY=from_root\n",
        encoding="utf-8",
    )

    engines_dir = tmp_path / "src" / "graft" / "engines"
    alpha_dir = engines_dir / "alpha"
    alpha_dir.mkdir(parents=True)
    (alpha_dir / ".env").write_text(
        "GRAFT_ALPHA_KEY=alpha_secret\nSHARED_KEY=from_alpha\n",
        encoding="utf-8",
    )

    hidden_dir = engines_dir / "_archived"
    hidden_dir.mkdir(parents=True)
    (hidden_dir / ".env").write_text("GRAFT_HIDDEN_KEY=should_not_load\n", encoding="utf-8")

    for k in ("GRAFT_LOG_LEVEL", "SHARED_KEY", "GRAFT_ALPHA_KEY", "GRAFT_HIDDEN_KEY"):
        monkeypatch.delenv(k, raising=False)

    try:
        loaded = load_env_file(engines_dir=engines_dir)
        assert loaded["GRAFT_LOG_LEVEL"] == "DEBUG"
        assert loaded["SHARED_KEY"] == "from_root"
        assert loaded["GRAFT_ALPHA_KEY"] == "alpha_secret"
        assert "GRAFT_HIDDEN_KEY" not in loaded
        assert os.environ["GRAFT_ALPHA_KEY"] == "alpha_secret"
    finally:
        for k in ("GRAFT_LOG_LEVEL", "SHARED_KEY", "GRAFT_ALPHA_KEY", "GRAFT_HIDDEN_KEY"):
            os.environ.pop(k, None)
