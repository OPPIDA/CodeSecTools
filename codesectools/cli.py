"""Defines the main command-line interface (CLI) for CodeSecTools.

This script sets up the main entry point for the application using `click`.
It dynamically discovers and adds CLI commands from all available SAST tools.
"""

import os

import click

from codesectools.sasts import SASTS_ALL
from codesectools.utils import PACKAGE_DIR, USER_DIR


class OrderedGroup(click.Group):
    """A click Group that lists commands in the order they were added."""

    def list_commands(self, ctx: click.Context) -> list:
        """List the command names in the order of definition.

        Args:
            ctx: The click context.

        Returns:
            A list of command names.

        """
        return self.commands.keys()


@click.group(cls=OrderedGroup)
@click.option(
    "-d", "--debug", required=False, is_flag=True, help="Show debugging messages"
)
def cli(debug: bool) -> None:
    """CodeSecTools."""
    if debug:
        os.environ["DEBUG"] = "1"


@cli.command()
def status() -> None:
    """Display SASTs and Datasets status."""
    click.echo(PACKAGE_DIR)
    click.echo(USER_DIR)


for _, sast_components in SASTS_ALL.items():
    cli.add_command(sast_components["cli"])
