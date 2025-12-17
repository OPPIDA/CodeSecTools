"""Defines the main command-line interface (CLI) for CodeSecTools.

This script sets up the main entry point for the application using `typer`.
It dynamically discovers and adds CLI commands from all available SAST tools.
"""

import os
import shutil
from pathlib import Path
from typing import Optional

import typer
import typer.completion
import typer.core
from click import Choice
from rich import print
from typing_extensions import Annotated

from codesectools.datasets import DATASETS_ALL
from codesectools.datasets.core.dataset import Dataset
from codesectools.sasts import SASTS_ALL
from codesectools.sasts.all.cli import build_cli as build_all_sast_cli
from codesectools.sasts.core.sast.requirements import DownloadableRequirement

typer.completion.completion_init()

CLI_NAME = "cstools"

COMPLETION_FILE = [
    Path.home() / ".bash_completions" / f"{CLI_NAME}.sh",
    Path.home() / f".zfunc/_{CLI_NAME}",
    Path.home() / f".config/fish/completions/{CLI_NAME}.fish",
]

cli = typer.Typer(
    name=CLI_NAME,
    no_args_is_help=True,
    add_help_option=False,
    add_completion=not any(f.is_file() for f in COMPLETION_FILE),
)


def version_callback(value: bool) -> None:
    """Print the application version and exit."""
    import importlib.metadata

    if value:
        print(importlib.metadata.version("codesectools"))
        raise typer.Exit()


@cli.callback()
def main(
    debug: Annotated[
        bool,
        typer.Option(
            "-d",
            "--debug",
            help="Show debugging messages and disable pretty exceptions.",
        ),
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
    """CodeSecTools CLI."""
    if debug:
        os.environ["DEBUG"] = "1"
        os.environ["_TYPER_STANDARD_TRACEBACK"] = "1"


@cli.command()
def status(
    sasts: Annotated[bool, typer.Option("--sasts", help="Show sasts only")] = False,
    datasets: Annotated[
        bool, typer.Option("--datasets", help="Show datasets only")
    ] = False,
) -> None:
    """Display the availability of SAST tools and datasets."""
    from rich.table import Table

    if sasts or (not sasts and not datasets):
        table = Table(show_lines=True)
        table.add_column("SAST", justify="center", no_wrap=True)
        table.add_column("Type", justify="center", no_wrap=True)
        table.add_column("Status", justify="center", no_wrap=True)
        table.add_column("Note", justify="center")
        for sast_name, sast_data in SASTS_ALL.items():
            if sast_data["status"] == "full":
                table.add_row(
                    sast_name,
                    sast_data["sast"].__bases__[0].__name__,
                    "Full ✅",
                    "[b]Analysis[/b] and [b]result parsing[/b] are available",
                )
            elif sast_data["status"] == "partial":
                table.add_row(
                    sast_name,
                    sast_data["sast"].__bases__[0].__name__,
                    "Partial ⚠️",
                    f"Only [b]result parsing[/b] is available\nMissing: [red]{sast_data['missing']}[/red]",
                )
            else:
                table.add_row(
                    sast_name,
                    sast_data["sast"].__bases__[0].__name__,
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

    Collects unfulfilled `DownloadableRequirement` instances from all SAST tools
    and un-cached `Dataset` instances.

    Returns:
        A dictionary mapping the resource name to its downloadable object.

    """
    downloadable = {}

    for _, sast_data in SASTS_ALL.items():
        sast = sast_data["sast"]
        for req in sast.requirements.all:
            if isinstance(req, DownloadableRequirement):
                if not req.is_fulfilled() and req.dependencies_fulfilled():
                    downloadable[req.name] = req

    for dataset_name, dataset in DATASETS_ALL.items():
        dataset_instance = dataset()
        if not dataset.is_cached():
            downloadable[dataset_name] = dataset_instance

    return downloadable


if DOWNLOADABLE := get_downloadable():
    download_hidden = False
    download_arg_type = str
    download_arg_value = typer.Argument(
        click_type=Choice(["all"] + list(DOWNLOADABLE)),
        metavar="NAME",
    )
else:
    download_hidden = True
    download_arg_type = Optional[str]
    download_arg_value = None


@cli.command(hidden=download_hidden)
def download(
    name: download_arg_type = download_arg_value,
    test: Annotated[bool, typer.Option(hidden=True)] = False,
) -> None:
    """Download and install any missing resources that are available for download."""
    if name is None:
        print("All downloadable resources have been retrieved.")
    else:
        if name == "all":
            targets = DOWNLOADABLE.values()
        else:
            targets = [DOWNLOADABLE[name]]

        for downloadable in targets:
            if isinstance(downloadable, DownloadableRequirement):
                downloadable.download()
            else:
                downloadable.download_dataset(test=test)


cli.add_typer(build_all_sast_cli())

if shutil.which("docker"):

    @cli.command()
    def docker(
        target: Annotated[Path, typer.Option()] = Path("."),
        isolation: Annotated[bool, typer.Option()] = False,
    ) -> None:
        """Start the Docker environment for the specified target (current directory by default)."""
        from codesectools.shared.docker import AnalysisEnvironment

        env = AnalysisEnvironment(isolation=isolation)
        env.start(target=target.resolve())


for _, sast_data in SASTS_ALL.items():
    cli.add_typer(sast_data["cli_factory"].build_cli())
