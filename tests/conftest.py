"""Defines shared fixtures and hooks for pytest."""

import hashlib
import json
import os
from pathlib import Path
from types import GeneratorType

import pytest

test_type = os.environ.get("TEST_TYPE")
state_file = Path(f".pytest_cache/state_{test_type}.json")


def gen_state() -> dict[str, str]:
    """Generate a state dictionary of source file paths and their SHA256 hashes.

    Monitors .py files in 'codesectools' and 'tests' directories.
    """
    state = {}
    for directory in ["codesectools", "tests"]:
        for code_path in Path(directory).rglob("*.py"):
            path = str(code_path)
            file_hash = hashlib.sha256(code_path.read_bytes()).hexdigest()
            state[path] = file_hash

    return state


def source_code_changed() -> bool:
    """Check if monitored source code has changed since the last successful test run.

    Compares the current state with a saved state in '.pytest_cache/state.json'.
    """
    if not state_file.is_file():
        return True

    with state_file.open("r") as f:
        try:
            old_state = json.load(f)
        except json.JSONDecodeError:
            return True

    new_state = gen_state()

    return new_state != old_state


def pytest_sessionstart(session: pytest.Session) -> None:
    """Pytest hook that runs at the beginning of a test session.

    Skips the entire test session if no source files have changed.
    """
    if not source_code_changed():
        pytest.exit("No changes in source code, skipping test session.", returncode=0)


@pytest.fixture(autouse=True, scope="session")
def constant_random() -> GeneratorType:
    """Set a constant random seed for reproducible tests."""
    os.environ["CONSTANT_RANDOM"] = os.urandom(16).hex()
    yield


def pytest_sessionfinish(session: pytest.Session) -> None:
    """Pytest hook that runs at the end of a test session.

    Saves the current source code state if the test session was successful.
    """
    if session.testscollected > 0 and session.testsfailed == 0:
        new_state = gen_state()
        state_file.parent.mkdir(exist_ok=True, parents=True)
        with state_file.open("w") as f:
            json.dump(new_state, f, indent=2)
