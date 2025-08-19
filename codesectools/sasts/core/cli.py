"""Provides a factory for building command-line interfaces for SAST tools.

This module contains the `CLIFactory` class, which simplifies the creation of
standardized `typer` CLI commands (analyze, benchmark, list, plot) for any
SAST integration.
"""

import shutil
from pathlib import Path
from typing import Self

import typer
from click import Choice
from typing_extensions import Annotated

from codesectools.datasets import DATASETS_ALL
from codesectools.datasets.core.dataset import FileDataset, GitRepoDataset
from codesectools.sasts.core.graphics import (
    FileDatasetGraphics,
    GitRepoDatasetGraphics,
    ProjectGraphics,
)
from codesectools.sasts.core.sast import SAST


class CLIFactory:
    """A factory to generate a standard set of CLI commands for a SAST tool.

    Attributes:
        cli (typer.Typer): The `typer` application to which commands will be added.
        sast (SAST): The SAST tool instance for which the CLI is being built.
        help_messages (dict): A dictionary of help messages for the standard commands.

    """

    def __init__(self, sast: SAST, custom_messages: dict) -> None:
        """Initialize the CLIFactory.

        Args:
            sast: An instance of the SAST tool's implementation class.
            custom_messages: A dictionary of custom help messages to override the defaults.

        """
        self.cli = typer.Typer(name=sast.name.lower(), no_args_is_help=True)
        self.sast = sast
        self.help_messages = {
            "main": f"""{sast.name}""",
            "analyze": f"""Analyze a project using {sast.name}.""",
            "benchmark": f"""Benchmark a dataset using {sast.name}.""",
            "list": """List existing analysis results.""",
            "plot": """Generate plot for results visualization.""",
        }
        self.help_messages.update(custom_messages)
        self._add_minimal()

    def _add_minimal(self: Self) -> None:
        """Add the minimal set of standard commands to the CLI."""
        self.add_main(help=self.help_messages["main"])
        self.add_analyze(help=self.help_messages["analyze"])
        self.add_list(help=self.help_messages["list"])
        self.add_benchmark(help=self.help_messages["benchmark"])
        self.add_plot(help=self.help_messages["plot"])

    def add_main(self: Self, help: str = "") -> None:
        """Add the main callback command to the CLI.

        This function sets up the main callback that runs when the SAST-specific
        command is invoked without a subcommand.

        Args:
            help: The help string for the main command.

        """

        @self.cli.callback(help=help)
        def main() -> None:
            pass

    ## Analyzer
    def add_analyze(self: Self, help: str = "") -> None:
        """Add the 'analyze' command to the CLI.

        This command runs the SAST tool on the current directory.

        Args:
            help: The help string for the command.

        """

        @self.cli.command(help=help)
        def analyze(
            lang: Annotated[
                str,
                typer.Argument(
                    click_type=Choice(self.sast.supported_languages),
                    help="Source code langauge (only one at the time)",
                    metavar="LANG",
                ),
            ],
            force: Annotated[
                bool,
                typer.Option(
                    "--force",
                    help="Overwrite existing analysis results for current project",
                ),
            ] = False,
        ) -> None:
            """Run SAST analysis on the project in the current working directory.

            Args:
                lang: The source code language to analyze.
                force: If True, overwrite any existing analysis results for the project.

            """
            output_dir = self.sast.output_dir / Path.cwd().name
            if output_dir.is_dir():
                typer.echo(f"Found existing analysis result at {output_dir}")
                if force:
                    shutil.rmtree(output_dir)
                    self.sast.run_analysis(lang, Path.cwd(), output_dir)
                else:
                    typer.echo("Use --force to overwrite it")
            else:
                self.sast.run_analysis(lang, Path.cwd(), output_dir)

    def add_benchmark(self, help: str = "") -> None:
        """Add the 'benchmark' command to the CLI.

        This command runs the SAST tool against a specified dataset.

        Args:
            help: The help string for the command.

        """

        @self.cli.command(help=help)
        def benchmark(
            dataset: Annotated[
                str,
                typer.Argument(
                    click_type=Choice(self.sast.list_supported_datasets()),
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
        ) -> None:
            """Run a SAST benchmark against a selected dataset.

            Args:
                dataset: The name of the dataset to use for benchmarking
                    (e.g., "BenchmarkJava_java").
                overwrite: If True, overwrite existing benchmark results.

            """
            dataset_name, lang = dataset.split("_")
            dataset = DATASETS_ALL[dataset_name](lang)
            if isinstance(dataset, FileDataset):
                self.sast.analyze_files(dataset, overwrite)
            elif isinstance(dataset, GitRepoDataset):
                self.sast.analyze_repos(dataset, overwrite)

    ## Parser
    def add_list(self, help: str = "") -> None:
        """Add the 'list' command to the CLI.

        This command lists all available analysis results for the SAST tool.

        Args:
            help: The help string for the command.

        """

        @self.cli.command(help=help)
        def results() -> None:
            """List available analysis results."""
            typer.echo("Available analysis results:")
            if self.sast.list_results(dataset=True, project=True):
                for dataset in self.sast.list_results(dataset=True):
                    typer.echo(f"- [Dataset] {dataset}")
                for project in self.sast.list_results(project=True):
                    typer.echo(f"- [Project] {project}")
            else:
                typer.echo("No analysis result available")

    # Graphics
    def add_plot(self, help: str = "") -> None:
        """Add the 'plot' command to the CLI.

        This command generates visualizations from analysis or benchmark results.

        Args:
            help: The help string for the command.

        """

        @self.cli.command(help=help)
        def plot(
            ctx: typer.Context,
            result: Annotated[
                str,
                typer.Argument(
                    click_type=Choice(
                        self.sast.list_results(project=True, dataset=True)
                    ),
                    metavar="RESULT",
                ),
            ],
            force: Annotated[
                bool,
                typer.Option(
                    "--force",
                    help="Force overwriting existing figures",
                ),
            ] = False,
            show: Annotated[
                bool,
                typer.Option(
                    "--show",
                    help="Display figures",
                ),
            ] = False,
            pgf: Annotated[
                bool,
                typer.Option(
                    "--pgf",
                    help="Export figures to pgf format (for LaTex document)",
                ),
            ] = False,
        ) -> None:
            """Generate and export plots for a given project or dataset result.

            Args:
                ctx: The Typer context.
                result: The name of the analysis result to plot.
                force: If True, overwrite existing figure files.
                show: If True, display the generated figures.
                pgf: If True, export figures in PGF format for LaTeX documents.

            """
            if result in self.sast.list_results(project=True):
                project = result
                project_graphics = ProjectGraphics(self.sast, project_name=project)
                project_graphics.export(force=force, show=show, pgf=pgf)
            elif result in self.sast.list_results(dataset=True):
                dataset = result
                dataset_name, lang = dataset.split("_")
                dataset = DATASETS_ALL[dataset_name](lang)
                if isinstance(dataset, FileDataset):
                    file_dataset_graphics = FileDatasetGraphics(
                        self.sast, dataset=dataset
                    )
                    file_dataset_graphics.export(force=force, show=show, pgf=pgf)
                elif isinstance(dataset, GitRepoDataset):
                    git_repo_dataset_graphics = GitRepoDatasetGraphics(
                        self.sast, dataset=dataset
                    )
                    git_repo_dataset_graphics.export(force=force, show=show, pgf=pgf)
                else:
                    typer.echo("Not supported yet")
