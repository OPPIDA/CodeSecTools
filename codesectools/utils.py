"""Provides utility functions, custom exceptions, and global configurations.

This module defines common file paths, a subprocess execution wrapper, custom
exception classes for handling common errors, and a global exception hook for
standardized error reporting.
"""

import os
import subprocess
import sys
import traceback
from importlib.resources import files
from pathlib import Path
from types import TracebackType

import click

# Package internal files
PACKAGE_DIR = Path(files("codesectools.utils"))

SHARED_DIR = PACKAGE_DIR / "shared"
SASTS_DIR = PACKAGE_DIR / "sasts"
DATASETS_DIR = PACKAGE_DIR / "datasets"

# User output directory
USER_DIR = Path.home() / ".codesectools"
USER_SASTS_DIR = USER_DIR / "sasts"
USER_DATASETS_DIR = USER_DIR / "datasets"
USER_RESULTS_DIR = USER_DIR / "results"


# Debugging
def DEBUG() -> bool:
    """Check if the application is in debug mode.

    Returns:
        True if the 'DEBUG' environment variable is set to '1', False otherwise.

    """
    return os.environ.get("DEBUG", "0") == "1"


# Subprocess wrapper
def run_command(command: list[str], cwd: Path) -> tuple[int | None, str]:
    """Execute a command in a subprocess and capture its output.

    Args:
        command: The command to execute, as a list of strings.
        cwd: The working directory for the command.

    Returns:
        A tuple containing the command's return code and its combined
        stdout/stderr output as a string.

    """
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    stdout = ""

    if process.stdout:
        for line in process.stdout:
            stdout += line
            if DEBUG():
                click.echo(line, nl=False)

    retcode = process.poll()

    return (retcode, stdout)


# Custom Exceptions
class MissingFile(Exception):
    """Exception raised when a required file is not found."""

    pass


class NonZeroExit(Exception):
    """Exception raised when a subprocess returns a non-zero exit code."""

    pass


# Global error handler
def global_excepthook(
    exc_type: type[BaseException],
    exc_value: BaseException,
    exc_traceback: TracebackType | None,
) -> None:
    """Handle uncaught exceptions globally.

    Provides custom, user-friendly error messages for specific exception types
    like `MissingFile` and `NonZeroExit`. Falls back to the default
    excepthook for other exceptions. If in debug mode, it prints the full traceback.

    Args:
        exc_type: The type of the exception.
        exc_value: The exception instance.
        exc_traceback: The traceback object.

    """
    if DEBUG():
        traceback.print_exception(exc_type, exc_value, exc_traceback)

    if issubclass(exc_type, MissingFile):
        files = exc_value.args[0]
        match len(files):
            case 1:
                click.echo(
                    f"[ERROR] File not found: {click.style(files[0], fg='red', bold=True)}",
                    err=True,
                )
            case _:
                click.echo(
                    f"[ERROR] Files not found: {click.style(', '.join(files), fg='red', bold=True)}",
                    err=True,
                )
    elif issubclass(exc_type, NonZeroExit):
        command, command_output = exc_value.args
        command = " ".join(str(c) for c in command)
        click.echo(
            f"[ERROR] Non zero return code while running command:\n{click.style(command, fg='red', bold=True)}",
            err=True,
        )
        click.echo(click.style(command_output, fg="red", italic=True), err=True)
    else:
        sys.__excepthook__(exc_type, exc_value, exc_traceback)


sys.excepthook = global_excepthook
