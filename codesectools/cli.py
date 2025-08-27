"""Defines the main command-line interface (CLI) for CodeSecTools.

This script sets up the main entry point for the application using `typer`.
It dynamically discovers and adds CLI commands from all available SAST tools.
"""

import importlib.metadata
import os
from typing import Optional

import typer
from rich import print
from rich.table import Table
from typing_extensions import Annotated

from codesectools.datasets import DATASETS_ALL
from codesectools.sasts import SASTS_ALL

cli = typer.Typer(name="cstools", no_args_is_help=True)


def version_callback(value: bool) -> None:
    """Print the application version and exit."""
    if value:
        print(importlib.metadata.version("codesectools"))
        raise typer.Exit()


@cli.callback()
def main(
    debug: Annotated[
        bool, typer.Option("-d", "--debug", help="Show debugging messages")
    ] = False,
    version: Annotated[
        Optional[bool],
        typer.Option(
            "-v",
            "--version",
            help="Show the tool's version.",
            callback=version_callback,
        ),
    ] = None,
) -> None:
    """CodeSecTools: A framework for code security that provides abstractions for static analysis tools and datasets to support their integration, testing, and evaluation."""
    if debug:
        os.environ["DEBUG"] = "1"


@cli.command()
def status(
    sasts: Annotated[bool, typer.Option("--sasts", help="Show sasts only")] = False,
    datasets: Annotated[
        bool, typer.Option("--datasets", help="Show datasets only")
    ] = False,
) -> None:
    """Display the availability status of SASTs and the cache status of datasets."""
    if sasts or (not sasts and not datasets):
        table = Table(show_lines=True)
        table.add_column("SAST", justify="center", no_wrap=True)
        table.add_column("Status", justify="center", no_wrap=True)
        table.add_column("Note", justify="center")
        for sast_name, sast_data in SASTS_ALL.items():
            if sast_data["status"] == "full":
                table.add_row(
                    sast_name, "Full ✅", f"See subcommand [b]{sast_name.lower()}[/b]"
                )
            elif sast_data["status"] == "partial":
                table.add_row(
                    sast_name,
                    "Partial ⚠️",
                    f"See subcommand [b]{sast_name.lower()}[/b]\nMissing: {sast_data['missing']}",
                )
            else:
                table.add_row(
                    sast_name,
                    "None ❌",
                    f"Missing: [b]{sast_data['missing']}[/b]",
                )
        print(table)

    if datasets or (not sasts and not datasets):
        table = Table(show_lines=True)
        table.add_column("Dataset", justify="center", no_wrap=True)
        table.add_column("Type", justify="center", no_wrap=True)
        table.add_column("Cached", justify="center", no_wrap=True)
        table.add_column("Note", justify="center")
        for dataset_name, dataset in DATASETS_ALL.items():
            if dataset.is_cached():
                table.add_row(
                    dataset_name,
                    dataset.__bases__[0].__name__,
                    "✅",
                    f"Supported languages: [b]{''.join(dataset.supported_languages)}[/b]",
                )
            else:
                table.add_row(
                    dataset_name,
                    dataset.__bases__[0].__name__,
                    "❌",
                    "Dataset is automatically downloaded when using it for the first time",
                )
        print(table)


for _, sast_data in SASTS_ALL.items():
    if sast_data["status"] != "none":
        cli.add_typer(sast_data["cli_factory"].build_cli())
