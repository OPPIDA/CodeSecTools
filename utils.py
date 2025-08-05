import os
import subprocess
import sys
import traceback
from types import TracebackType

import click

# Use current working directory
WORKING_DIR = os.environ.get("WORKING_DIR", "")
if not WORKING_DIR:
    click.echo("Fatal error: WORKING_DIR is not defined!", err=True)
    sys.exit(1)


# Debugging
def DEBUG() -> bool:
    return os.environ.get("DEBUG", "0") == "1"


# Subprocess wrapper
def run_command(command: list[str], cwd: str) -> tuple[int | None, str]:
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
    pass


class NonZeroExit(Exception):
    pass


# Global error handler
def global_excepthook(
    exc_type: type[BaseException],
    exc_value: BaseException,
    exc_traceback: TracebackType | None,
) -> None:
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
        click.echo(
            f"[ERROR] Non zero return code while running command:\n{click.style(' '.join(command), fg='red', bold=True)}",
            err=True,
        )
        click.echo(click.style(command_output, fg="red", italic=True), err=True)
    else:
        sys.__excepthook__(exc_type, exc_value, exc_traceback)


sys.excepthook = global_excepthook
