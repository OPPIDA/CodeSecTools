"""Defines the command-line interface for the Bearer integration.

This script sets up the `typer` command group for Bearer and uses the
`CLIFactory` to generate the standard set of subcommands (analyze, benchmark, etc.).
"""

from codesectools.sasts.Bearer.sast import BearerSAST
from codesectools.sasts.core.cli import CLIFactory

BearerCLIFactory = CLIFactory(BearerSAST(), custom_messages={"main": "Bearer SAST"})
