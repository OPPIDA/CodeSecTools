"""Defines the command-line interface for the Snyk Code integration.

This script sets up the `typer` command group for Snyk Code and uses the
`CLIFactory` to generate the standard set of subcommands (analyze, benchmark, etc.).
"""

from codesectools.sasts.core.cli import CLIFactory
from codesectools.sasts.tools.SnykCode.sast import SnykCodeSAST

SnykCodeCLIFactory = CLIFactory(SnykCodeSAST(), custom_messages={"main": "Snyk Code"})
