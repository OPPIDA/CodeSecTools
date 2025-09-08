"""Defines the command-line interface for running all available SASTs."""

import shutil
from pathlib import Path

import typer
from click import Choice
from rich import print
from rich.table import Table
from typing_extensions import Annotated

from codesectools.datasets import DATASETS_ALL
from codesectools.datasets.core.dataset import FileDataset, GitRepoDataset
from codesectools.sasts import SASTS_ALL
from codesectools.sasts.all.graphics import ProjectGraphics
from codesectools.sasts.all.sast import AllSAST

cli = typer.Typer(name="allsast", no_args_is_help=True)
all_sast = AllSAST()


@cli.callback()
def main() -> None:
    """Run all available SASTs together."""
    pass


@cli.command(help="List used SASTs.")
def info() -> None:
    """Display the status of all SASTs and their inclusion in AllSAST."""
    table = Table(show_lines=True)
    table.add_column("SAST", justify="center", no_wrap=True)
    table.add_column("Status", justify="center", no_wrap=True)
    table.add_column("Note", justify="center")
    for sast_name, sast_data in SASTS_ALL.items():
        if sast_data["status"] == "full":
            table.add_row(
                sast_name,
                "Full",
                "[b]Included ✅[/b] in AllSAST",
            )
        elif sast_data["status"] == "partial":
            table.add_row(
                sast_name,
                "Partial",
                f"[b]Not included ❌[/b] is available\nMissing: [red]{sast_data['missing']}[/red]",
            )
        else:
            table.add_row(
                sast_name,
                "None",
                f"[b]Not included ❌[/b] is available\nMissing: [red]{sast_data['missing']}[/red]",
            )
    print(table)


@cli.command(help="Analyze a project using all availbale SASTs.")
def analyze(
    lang: Annotated[
        str,
        typer.Argument(
            click_type=Choice(all_sast.supported_languages),
            help="Source code language (only one at the time)",
            metavar="LANG",
        ),
    ],
    overwrite: Annotated[
        bool,
        typer.Option(
            "--overwrite",
            help="Overwrite existing analysis results for current project",
        ),
    ] = False,
) -> None:
    """Run analysis on the current project with all available SASTs."""
    for sast in all_sast.sasts:
        output_dir = sast.output_dir / Path.cwd().name
        if output_dir.is_dir():
            if overwrite:
                shutil.rmtree(output_dir)
                sast.run_analysis(lang, Path.cwd(), output_dir)
            else:
                print(f"Found existing analysis result at {output_dir}")
                print("Use --overwrite to overwrite it")
        else:
            sast.run_analysis(lang, Path.cwd(), output_dir)


@cli.command(help="Benchmark a dataset using all SASTs.")
def benchmark(
    dataset: Annotated[
        str,
        typer.Argument(
            click_type=Choice(all_sast.supported_dataset_full_names),
            metavar="DATASET",
        ),
    ],
    overwrite: Annotated[
        bool,
        typer.Option(
            "--overwrite",
            help="Overwrite existing results (not applicable on CVEfixes)",
        ),
    ] = False,
    testing: Annotated[
        bool,
        typer.Option(
            "--testing",
            help="Run benchmark over a single dataset unit for testing",
        ),
    ] = False,
) -> None:
    """Run a benchmark on a dataset using all available SASTs."""
    dataset_name, lang = dataset.split("_")
    for sast in all_sast.sasts:
        dataset = DATASETS_ALL[dataset_name](lang)
        if isinstance(dataset, FileDataset):
            sast.analyze_files(dataset, overwrite, testing)
        elif isinstance(dataset, GitRepoDataset):
            sast.analyze_repos(dataset, overwrite, testing)


@cli.command(help="List existing analysis results.")
def list() -> None:
    """List existing analysis results for projects and datasets."""
    table = Table(show_lines=True)
    table.add_column("Name", justify="center", no_wrap=True)
    table.add_column("Type", justify="center", no_wrap=True)
    table.add_column("Analyzed with", justify="center", no_wrap=True)

    for dataset_full_name in all_sast.list_results(dataset=True):
        table.add_row(
            dataset_full_name,
            "Dataset",
            ", ".join(f"[b]{sast.name}[/b]" for sast in all_sast.sasts),
        )
    for project in all_sast.list_results(project=True):
        table.add_row(
            project,
            "Project",
            ", ".join(f"[b]{sast.name}[/b]" for sast in all_sast.sasts),
        )

    print(table)


@cli.command(
    help="Generate plot for results visualization (datasets are not supported)."
)
def plot(
    result: Annotated[
        str,
        typer.Argument(
            click_type=Choice(all_sast.list_results(project=True)),
            metavar="RESULT",
        ),
    ],
) -> None:
    """Generate and display plots for a project's aggregated analysis results."""
    if result in all_sast.list_results(project=True):
        project = result
        project_graphics = ProjectGraphics(project_name=project)
        project_graphics.show()
