"""Provides utility functions, custom exceptions, and global configurations.

This module defines common file paths, a subprocess execution wrapper, custom
exception classes for handling common errors, and a global exception hook for
standardized error reporting.
"""

import os
import re
import subprocess
from collections.abc import Sequence
from importlib.resources import files
from pathlib import Path

import click

# Package internal files
PACKAGE_DIR = Path(str(files("codesectools.utils")))
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
def get_pattern(arg: str, mapping: dict[str, str]) -> str | None:
    """Find a placeholder pattern like '{placeholder}' in an argument string.

    Args:
        arg: The string to search for a pattern.
        mapping: A dictionary of placeholders, kept for contextual consistency
                 with `render_command`.

    Returns:
        The found pattern string (e.g., '{placeholder}') or None if not found.

    """
    if m := re.search(r"\{.*\}", arg):
        return m.group(0)


def render_command(command: list, mapping: dict[str, str]) -> list[str]:
    """Render a command template by replacing placeholders with values.

    Substitutes placeholders in a command list from a given map. It handles
    simple string arguments and optional arguments represented as tuples.
    If a mapped value is a list, the argument is expanded.

    Args:
        command: The command template, which can contain strings and tuples
            of the form `(default, optional_template)`.
        mapping: A dictionary of placeholders to their replacement values.

    Returns:
        The rendered command as a list of strings.

    """
    _command = command.copy()
    for i, arg in enumerate(_command):
        # Check if optional argument can be used
        if isinstance(arg, tuple):
            default_arg, optional_arg = arg

            if pattern := get_pattern(optional_arg, mapping):
                _command[i] = optional_arg.replace(pattern, mapping[pattern])
            elif pattern := get_pattern(default_arg, mapping):
                _command[i] = default_arg.replace(pattern, mapping[pattern])
        else:
            if pattern := get_pattern(arg, mapping):
                value = mapping[pattern]
                if isinstance(value, list):
                    _command[i] = " ".join(
                        arg.replace(pattern, subvalue) for subvalue in value
                    )
                else:
                    _command[i] = arg.replace(pattern, value)

    _command = " ".join(_command).split(" ")

    # Remove not rendered part of the command:
    __command = []
    for part in _command:
        if not ("{" in part and "}" in part):
            __command.append(part)

    return __command


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


def group_successive(numbers_list: list[int]) -> list[list[int]]:
    """Group a list of integers into sublists of consecutive numbers.

    For example, `[1, 2, 4, 5, 6, 8]` becomes `[[1, 2], [4, 5, 6], [8]]`.

    Args:
        numbers_list: A list of integers.

    Returns:
        A list of lists, where each sublist contains consecutive integers.

    """
    if not numbers_list:
        return []

    sorted_list = sorted(list(set(numbers_list)))

    groups = []
    current_group = [sorted_list[0]]

    for i in range(1, len(sorted_list)):
        if sorted_list[i] == current_group[-1] + 1:
            current_group.append(sorted_list[i])
        else:
            groups.append(current_group)
            current_group = [sorted_list[i]]

    groups.append(current_group)

    return groups


def shorten_path(path: str, max_len: int = 20) -> str:
    """Shorten a file path for display if it's too long.

    Args:
        path: The file path to shorten.
        max_len: The maximum length allowed for the path string.

    Returns:
        The shortened path string, potentially prefixed with an ellipsis.

    """
    original_path = Path(path)
    shortened_path = Path(original_path.parts[-1])

    for i in range(-2, -len(original_path.parts) - 1, -1):
        if len(str(Path(original_path.parts[i], shortened_path))) < max_len:
            shortened_path = Path(original_path.parts[i], shortened_path)
        else:
            break

    if shortened_path != shortened_path.absolute():
        shortened_path = Path("...", shortened_path)

    return str(shortened_path)


CPU_COUNT = os.cpu_count()
