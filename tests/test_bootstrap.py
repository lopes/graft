"""Bootstrap smoke tests verifying test harness and environment."""

import sys

import pytest

import graft


def test_python_version() -> None:
    assert sys.version_info >= (3, 13)


def test_package_metadata() -> None:
    assert graft.__version__ == "0.1.0"


@pytest.mark.integration
def test_integration_marker_skip() -> None:
    # Gated by --run-integration flag in conftest.py
    assert True
