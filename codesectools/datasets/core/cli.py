"""Defines the command-line interface for dataset management."""

import typer
from click import Choice
from rich import print
from typing_extensions import Annotated

from codesectools.datasets import DATASETS_ALL

cli = typer.Typer(name="dataset", no_args_is_help=True)


@cli.callback()
def main() -> None:
    """Dataset management."""
    pass


@cli.command()
def download(
    dataset_name: Annotated[
        str,
        typer.Argument(
            click_type=Choice(["all"] + list(DATASETS_ALL.keys())), metavar="DATASET"
        ),
    ],
) -> None:
    """Download and cache one or all datasets."""
    if dataset_name == "all":
        datasets = DATASETS_ALL.items()
    else:
        datasets = {dataset_name: DATASETS_ALL[dataset_name]}

    for dataset_name, dataset in datasets:
        dataset_instance = dataset()
        if not dataset.is_cached():
            try:
                dataset_instance.download_dataset()
            except typer.Exit:
                continue
        else:
            print(
                f"{dataset_name} is already downloaded at {dataset_instance.directory}."
            )
