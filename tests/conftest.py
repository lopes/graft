"""Pytest configuration and custom command-line options."""

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run live API integration tests",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--run-integration"):
        return
    skip_integration = pytest.mark.skip(reason="Pass --run-integration to run live tests")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)


@pytest.fixture(autouse=True)
def _isolate_local_env_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("graft.cli.main.load_env_file", lambda *args, **kwargs: {})
