"""Defines the command-line interface for the Semgrep Community Edition integration.

This script sets up the `click` command group for Semgrep Community Edition and uses the
`CLIFactory` to generate the standard set of subcommands (analyze, benchmark, etc.).
"""

import click

from codesectools.sasts.core.cli import CLIFactory
from codesectools.sasts.SemgrepCE.sast import SemgrepCESAST


@click.group(name="semgrepce")
def SemgrepCECLI() -> None:
    """Semgrep Community Edition Engine."""
    pass


CLIFactory(SemgrepCECLI, SemgrepCESAST(), custom_messages={})
