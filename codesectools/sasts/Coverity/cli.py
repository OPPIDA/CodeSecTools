"""Defines the command-line interface for the Coverity integration.

This script sets up the `click` command group for Coverity and uses the
`CLIFactory` to generate the standard set of subcommands (analyze, benchmark, etc.).
"""

import click

from codesectools.sasts.core.cli import CLIFactory
from codesectools.sasts.Coverity.sast import CoveritySAST


@click.group(name="coverity")
def CoverityCLI() -> None:
    """Coverity Static Analysis."""
    pass


CLIFactory(CoverityCLI, CoveritySAST(), custom_messages={})
