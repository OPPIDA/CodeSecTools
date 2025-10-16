"""Provides utility functions, custom exceptions, and global configurations.

This module defines common file paths, a subprocess execution wrapper, custom
exception classes for handling common errors, and a global exception hook for
standardized error reporting.
"""

import os
import subprocess
from collections.abc import Sequence
from importlib.resources import files
from pathlib import Path

import click

# Package internal files
PACKAGE_DIR = Path(files("codesectools.utils"))
DATA_DIR = PACKAGE_DIR / "data"
SHARED_DIR = PACKAGE_DIR / "shared"
SASTS_DIR = PACKAGE_DIR / "sasts"
DATASETS_DIR = PACKAGE_DIR / "datasets"

# User output directory
USER_DIR = Path.home() / ".codesectools"
USER_CONFIG_DIR = USER_DIR / "config"
USER_CACHE_DIR = USER_DIR / "cache"
USER_OUTPUT_DIR = USER_DIR / "output"


# Debugging
def DEBUG() -> bool:
    """Check if the application is in debug mode.

    Returns:
        True if the 'DEBUG' environment variable is set to '1', False otherwise.

    """
    return os.environ.get("DEBUG", "0") == "1"


# Subprocess wrapper
def run_command(
    command: Sequence[str], cwd: Path, env: dict[str, str] | None = None
) -> tuple[int | None, str]:
    """Execute a command in a subprocess and capture its output.

    Args:
        command: The command to execute, as a list of strings.
        cwd: The working directory for the command.
        env: Optional dictionary of environment variables to set for the command.

    Returns:
        A tuple containing the command's return code and its combined
        stdout/stderr output as a string.

    """
    modified_env = {**os.environ, **env} if env else os.environ

    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=modified_env,
    )

    stdout = ""

    if process.stdout:
        for line in process.stdout:
            stdout += line
            if DEBUG():
                click.echo(line, nl=False)

    process.wait()
    retcode = process.poll()

    return (retcode, stdout)


# Custom Exceptions
class MissingFile(Exception):
    """Exception raised when a required file is not found."""

    def __init__(self, files: list[str]) -> None:
        """Initialize the MissingFile exception.

        Args:
            files: A list of file paths that were not found.

        """
        self.files = files

    def __str__(self) -> str:
        """Return a user-friendly string representation of the exception."""
        match len(self.files):
            case 1:
                return f"File not found: {self.files[0]}"
            case _:
                return f"Files not found: {', '.join(self.files)}"


class NonZeroExit(Exception):
    """Exception raised when a subprocess returns a non-zero exit code."""

    def __init__(self, command: list[str], command_output: str) -> None:
        """Initialize the NonZeroExit exception.

        Args:
            command: The command that was executed, as a list of strings.
            command_output: The captured stdout/stderr from the command.

        """
        self.command = " ".join(str(c) for c in command)
        self.command_output = command_output

    def __str__(self) -> str:
        """Return a user-friendly string representation of the exception."""
        return f"Non zero return code while running command:\n{self.command}\n{self.command_output}"
