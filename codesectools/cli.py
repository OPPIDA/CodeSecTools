"""Defines the main command-line interface (CLI) for CodeSecTools.

This script sets up the main entry point for the application using `typer`.
It dynamically discovers and adds CLI commands from all available SAST tools.
"""

import os

import typer
from typing_extensions import Annotated

from codesectools.datasets import DATASETS_ALL
from codesectools.sasts import SASTS_ALL

cli = typer.Typer(no_args_is_help=True)


@cli.callback()
def main(
    debug: Annotated[
        bool, typer.Option("-d", "--debug", help="Show debugging messages")
    ] = False,
) -> None:
    """CodeSecTools: A framework for code security that provides abstractions for static analysis tools and datasets to support their integration, testing, and evaluation."""
    if debug:
        os.environ["DEBUG"] = "1"


@cli.command()
def status() -> None:
    """Display SASTs and Datasets status."""
    typer.echo("Available SASTs:")
    for sast_name, _ in SASTS_ALL.items():
        typer.echo(f" - {sast_name}")

    typer.echo("Available datasets:")
    for dataset_name, dataset in DATASETS_ALL.items():
        typer.echo(f" - {dataset_name} ({' '.join(dataset.supported_languages)})")


for _, sast_components in SASTS_ALL.items():
    cli.add_typer(sast_components["cli"])
