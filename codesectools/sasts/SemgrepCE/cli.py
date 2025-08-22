"""Defines the command-line interface for the Semgrep Community Edition integration.

This script sets up the `typer` command group for Semgrep Community Edition and uses the
`CLIFactory` to generate the standard set of subcommands (analyze, benchmark, etc.).
"""

from codesectools.sasts.core.cli import CLIFactory
from codesectools.sasts.SemgrepCE.sast import SemgrepCESAST

SemgrepCECLIFactory = CLIFactory(
    SemgrepCESAST(), custom_messages={"main": "Semgrep Community Edition Engine"}
)
