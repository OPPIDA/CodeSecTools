"""Defines the command-line interface for the Coverity integration.

This script sets up the `typer` command group for Coverity and uses the
`CLIFactory` to generate the standard set of subcommands (analyze, benchmark, etc.).
"""

from codesectools.sasts.core.cli import CLIFactory
from codesectools.sasts.tools.Coverity.sast import CoveritySAST

CoverityCLIFactory = CLIFactory(
    CoveritySAST(), custom_messages={"main": "Coverity Static Analysis"}
)
