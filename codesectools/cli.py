"""Defines the main command-line interface (CLI) for CodeSecTools.

This script sets up the main entry point for the application using `typer`.
It dynamically discovers and adds CLI commands from all available SAST tools.
"""

import importlib.metadata
import os
from typing import Optional

import typer
from click import Choice
from rich import print
from rich.table import Table
from typing_extensions import Annotated

from codesectools.datasets import DATASETS_ALL
from codesectools.datasets.core.dataset import Dataset
from codesectools.sasts import SASTS_ALL
from codesectools.sasts.core.sast.requirements import DownloadableRequirement

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
                    sast_name,
                    "Full ✅",
                    "[b]Analysis[/b] and [b]result parsing[/b] are available",
                )
            elif sast_data["status"] == "partial":
                table.add_row(
                    sast_name,
                    "Partial ⚠️",
                    f"Only [b]result parsing[/b] is available\nMissing: [red]{sast_data['missing']}[/red]",
                )
            else:
                table.add_row(
                    sast_name,
                    "None ❌",
                    f"[b]Nothing[/b] is available\nMissing: [red]{sast_data['missing']}[/red]",
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
                    f"Download with: [i red]cstools download {dataset_name}[/i red]",
                )
        print(table)


def get_downloadable() -> dict[str, DownloadableRequirement | Dataset]:
    """Identify and collect all missing downloadable resources.

    Collects unfulfilled `DownloadableRequirement` instances from all SASTs
    and un-cached `Dataset` instances.

    Returns:
        A dictionary mapping the resource name to its downloadable object.

    """
    downloadable = {}

    for _, sast_data in SASTS_ALL.items():
        sast = sast_data["sast"]
        for req in sast.requirements.all:
            if isinstance(req, DownloadableRequirement):
                if not req.is_fulfilled():
                    downloadable[req.name] = req

    for dataset_name, dataset in DATASETS_ALL.items():
        dataset_instance = dataset()
        if not dataset.is_cached():
            downloadable[dataset_name] = dataset_instance

    return downloadable


if DOWNLOADABLE := get_downloadable():

    @cli.command()
    def download(
        name: Annotated[
            str,
            typer.Argument(
                click_type=Choice(["all"] + list(DOWNLOADABLE)),
                metavar="NAME",
            ),
        ],
    ) -> None:
        """Download missing resources."""
        if name == "all":
            targets = DOWNLOADABLE.values()
        else:
            targets = [DOWNLOADABLE[name]]

        for downloadable in targets:
            if isinstance(downloadable, DownloadableRequirement):
                downloadable.download()
            else:
                downloadable.download_dataset()


for _, sast_data in SASTS_ALL.items():
    cli.add_typer(sast_data["cli_factory"].build_cli())
