# TODO: TO REWORK
import shutil
from pathlib import Path

import click

from sastbenchmark.datasets import DATASETS_ALL
from sastbenchmark.datasets._core.dataset import FileDataset, GitRepoDataset
from sastbenchmark.sasts._core.graphics import (
    FileDatasetGraphics,
    GitRepoDatasetGraphics,
    ProjectGraphics,
)
from sastbenchmark.sasts._core.sast import SAST


class CLIFactory:
    def __init__(self, cli: click.Group, sast: SAST, help_messages: dict) -> None:
        self.cli = cli
        self.sast = sast
        # TODO: provide default help_messages
        self._add_minimal(help_messages)

    def _add_minimal(self, help_messages: dict) -> None:
        self.add_analyze(help=help_messages["analyze"])
        self.add_list(help=help_messages["list"])
        self.add_benchmark(help=help_messages["benchmark"])
        self.add_plot(help=help_messages["plot"])

    ## Analyzer
    def add_analyze(self, help: str = "") -> None:
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
            result_dir = self.sast.result_dir / Path.cwd().name
            if result_dir.is_dir():
                click.echo(f"Found existing analysis result at {result_dir}")
                if force:
                    shutil.rmtree(result_dir)
                    self.sast.run_analysis(lang, Path.cwd(), result_dir)
                else:
                    click.echo("Use --force to overwrite it")
            else:
                self.sast.run_analysis(lang, Path.cwd(), result_dir)

    def add_benchmark(self, help: str = "") -> None:
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
            dataset_name, lang = dataset.split("_")
            dataset = DATASETS_ALL[dataset_name](lang)
            if isinstance(dataset, FileDataset):
                self.sast.analyze_files(dataset, overwrite)
            elif isinstance(dataset, GitRepoDataset):
                self.sast.analyze_repos(dataset, overwrite)

    ## Parser
    def add_list(self, help: str = "") -> None:
        @self.cli.command(name="list", help=help)
        def list_() -> None:
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
