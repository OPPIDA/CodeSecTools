"""Defines the command-line interface for the Semgrep integration.

This script sets up the `click` command group for Semgrep and uses the
`CLIFactory` to generate the standard set of subcommands (analyze, benchmark, etc.).
"""

import click

from codesectools.sasts.core.cli import CLIFactory
from codesectools.sasts.Semgrep.sast import SemgrepSAST


@click.group(name="semgrep")
def SemgrepCLI() -> None:
    """Semgrep Pro Engine."""
    pass


CLIFactory(SemgrepCLI, SemgrepSAST(), custom_messages={})
