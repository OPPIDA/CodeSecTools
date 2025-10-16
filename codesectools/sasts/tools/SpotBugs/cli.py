"""Defines the command-line interface for the SpotBugs integration.

This script sets up the `typer` command group for SpotBugs and uses the
`CLIFactory` to generate the standard set of subcommands (analyze, benchmark, etc.).
"""

from codesectools.sasts.core.cli import CLIFactory
from codesectools.sasts.tools.SpotBugs.sast import SpotBugsSAST

SpotBugsCLIFactory = CLIFactory(SpotBugsSAST(), custom_messages={"main": "SpotBugs"})
