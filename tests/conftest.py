"""Defines shared fixtures and hooks for pytest."""

import logging
import os
import shutil
from pathlib import Path
from types import GeneratorType

import pytest

# Fix: I/O operation on closed (https://github.com/pallets/click/issues/824)
logging.getLogger("matplotlib").setLevel(logging.ERROR)


def pytest_sessionstart(session: pytest.Session) -> None:
    """Initialize the test session by copying test codes to a temporary directory."""
    shutil.copytree(Path("tests/testcodes"), Path("/tmp/tests/testcodes"))


@pytest.fixture(autouse=True, scope="session")
def constant_random() -> GeneratorType:
    """Set a constant random seed for reproducible tests."""
    os.environ["CONSTANT_RANDOM"] = os.urandom(16).hex()
    yield
