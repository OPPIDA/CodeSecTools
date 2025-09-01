"""Defines shared fixtures for pytest."""

import os
from types import GeneratorType

import pytest


@pytest.fixture(autouse=True, scope="session")
def constant_random() -> GeneratorType:
    """Set a constant random seed for reproducible tests."""
    os.environ["CONSTANT_RANDOM"] = os.urandom(16).hex()

    yield
