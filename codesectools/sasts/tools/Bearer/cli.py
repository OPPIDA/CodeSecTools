"""Defines the command-line interface for the Bearer integration.

This script sets up the `typer` command group for Bearer and uses the
`CLIFactory` to generate the standard set of subcommands (analyze, benchmark, etc.).
"""

from codesectools.sasts.core.cli import CLIFactory
from codesectools.sasts.tools.Bearer.sast import BearerSAST

BearerCLIFactory = CLIFactory(BearerSAST(), custom_messages={"main": "Bearer SAST"})
