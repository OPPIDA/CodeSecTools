"""Provides a factory for building command-line interfaces for SAST tools.

This module contains the `CLIFactory` class, which simplifies the creation of
standardized `click` CLI commands (analyze, benchmark, list, plot) for any
SAST integration.
"""

import shutil
from pathlib import Path
from typing import Self

import click

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
        cli (click.Group): The `click` group to which commands will be added.
        sast (SAST): The SAST tool instance for which the CLI is being built.
        help_messages (dict): A dictionary of help messages for the standard commands.

    """

    def __init__(self, cli: click.Group, sast: SAST, custom_messages: dict) -> None:
        """Initialize the CLIFactory.

        Args:
            cli: The `click` command group to attach the new commands to.
            sast: An instance of the SAST tool's implementation class.
            custom_messages: A dictionary of custom help messages to override the defaults.

        """
        self.cli = cli
        self.sast = sast
        self.help_messages = {
            "analyze": f"""Analyze a project using {sast.name}.""",
            "benchmark": f"""Benchmark a dataset using {sast.name}.""",
            "list": """List existing analysis results.""",
            "plot": """Generate plot for visualization.""",
        }
        self.help_messages.update(custom_messages)
        self._add_minimal()

    def _add_minimal(self: Self) -> None:
        """Add the minimal set of standard commands to the CLI group."""
        self.add_analyze(help=self.help_messages["analyze"])
        self.add_list(help=self.help_messages["list"])
        self.add_benchmark(help=self.help_messages["benchmark"])
        self.add_plot(help=self.help_messages["plot"])

    ## Analyzer
    def add_analyze(self, help: str = "") -> None:
        """Add the 'analyze' command to the CLI.

        This command runs the SAST tool on the current directory.

        Args:
            help: The help string for the command.

        """

        @self.cli.command(no_args_is_help=True, help=help)
        @click.option(
            "--lang",
            required=True,
            type=click.Choice(self.sast.supported_languages),
            show_choices=True,
            help="Source code langauge (only one at the time)",
        )
        @click.option(
            "--force",
            required=False,
            is_flag=True,
            help="Overwrite existing analysis results for current project",
        )
        def analyze(lang: str, force: bool) -> None:
            """Run SAST analysis on the current directory."""
            output_dir = self.sast.output_dir / Path.cwd().name
            if output_dir.is_dir():
                click.echo(f"Found existing analysis result at {output_dir}")
                if force:
                    shutil.rmtree(output_dir)
                    self.sast.run_analysis(lang, Path.cwd(), output_dir)
                else:
                    click.echo("Use --force to overwrite it")
            else:
                self.sast.run_analysis(lang, Path.cwd(), output_dir)

    def add_benchmark(self, help: str = "") -> None:
        """Add the 'benchmark' command to the CLI.

        This command runs the SAST tool against a specified dataset.

        Args:
            help: The help string for the command.

        """

        @self.cli.command(help=help)
        @click.option(
            "--dataset",
            required=True,
            type=click.Choice(self.sast.list_supported_datasets()),
        )
        @click.option(
            "--overwrite",
            required=False,
            is_flag=True,
            help="Overwrite existing results (not applicable on CVEfixes)",
        )
        def benchmark(dataset: str, overwrite: bool) -> None:
            """Run SAST benchmark against a selected dataset."""
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

        @self.cli.command(name="list", help=help)
        def list_() -> None:
            """List available analysis results."""
            click.echo("Available analysis results:")
            if self.sast.list_results(dataset=True, project=True):
                for dataset in self.sast.list_results(dataset=True):
                    click.echo(f"- [Dataset] {dataset}")
                for project in self.sast.list_results(project=True):
                    click.echo(f"- [Project] {project}")
            else:
                click.echo("No analysis result available")

    # Graphics
    def add_plot(self, help: str = "") -> None:
        """Add the 'plot' command to the CLI.

        This command generates visualizations from analysis or benchmark results.

        Args:
            help: The help string for the command.

        """

        @self.cli.command(help=help)
        @click.option(
            "--project",
            type=click.Choice(self.sast.list_results(project=True)),
            help="Project name",
        )
        @click.option(
            "--dataset",
            type=click.Choice(self.sast.list_results(dataset=True)),
            help="Dataset name",
        )
        @click.option(
            "--force",
            required=False,
            is_flag=True,
            default=False,
            help="Force overwriting existing figures",
        )
        @click.option(
            "--show",
            required=False,
            is_flag=True,
            default=False,
            help="Display figures",
        )
        @click.option(
            "--pgf",
            required=False,
            is_flag=True,
            default=False,
            help="Export figures to pgf format (for LaTex document)",
        )
        @click.pass_context
        def plot(
            ctx: click.Context,
            project: str,
            dataset: str,
            force: bool,
            show: bool,
            pgf: bool,
        ) -> None:
            """Generate and export plots for a given project or dataset result."""
            if (project is None) and (dataset is None):
                click.echo(
                    "Please provide at least a project or dataset name with --project/--dataset"
                )
                ctx.invoke(self.cli.commands["list"])
            elif project and dataset:
                click.echo("Please provide only one project or one dataset name")

            elif project:
                project_graphics = ProjectGraphics(self.sast, project_name=project)
                project_graphics.export(force=force, show=show, pgf=pgf)
            else:
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
                    click.echo("Not supported yet")
