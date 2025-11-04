"""Defines the command-line interface for the Cppcheck integration.

This script sets up the `typer` command group for Cppcheck and uses the
`CLIFactory` to generate the standard set of subcommands (analyze, benchmark, etc.).
"""

from codesectools.sasts.core.cli import CLIFactory
from codesectools.sasts.tools.Cppcheck.sast import CppcheckSAST

CppcheckCLIFactory = CLIFactory(CppcheckSAST(), custom_messages={"main": "Cppcheck"})
