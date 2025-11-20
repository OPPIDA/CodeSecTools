"""Provides a factory for building command-line interfaces for SAST tools.

This module contains the `CLIFactory` class, which simplifies the creation of
standardized `typer` CLI commands (analyze, benchmark, list, plot) for any
SAST integration.
"""

import shutil
from pathlib import Path
from typing import Optional, Self

import typer
from click import Choice
from rich import print
from typing_extensions import Annotated, Literal

from codesectools.datasets import DATASETS_ALL
from codesectools.datasets.core.dataset import FileDataset, GitRepoDataset
from codesectools.sasts.core.sast import SAST, PrebuiltBuildlessSAST, PrebuiltSAST


class CLIFactory:
    """Provide a factory to generate a standard set of CLI commands for a SAST tool.

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
        self.sast = sast
        self.help_messages = {
            "main": f"""{sast.name}""",
            "install": "List instruction to install missing requirements.",
            "analyze": f"""Analyze a project using {sast.name}.""",
            "benchmark": f"""Benchmark a dataset using {sast.name}.""",
            "list": """List existing analysis results.""",
            "plot": """Generate plot for results visualization.""",
        }
        self.help_messages.update(custom_messages)
        self.build_cli()

    def build_cli(self) -> typer.Typer:
        """Build and return the Typer CLI application for the SAST tool."""
        self.cli = typer.Typer(name=self.sast.name.lower(), no_args_is_help=True)
        self._add_minimal()
        return self.cli

    def _add_minimal(self: Self) -> None:
        """Add the minimal set of standard commands based on the SAST tool's status."""
        self.add_main(help=self.help_messages["main"])
        if self.sast.status == "full":
            self.add_analyze(help=self.help_messages["analyze"])
            self.add_benchmark(help=self.help_messages["benchmark"])
            self.add_list(help=self.help_messages["list"])
            self.add_plot(help=self.help_messages["plot"])
        elif self.sast.status == "partial":
            self.add_install(help=self.help_messages["install"])
            self.add_list(help=self.help_messages["list"])
            self.add_plot(help=self.help_messages["plot"])
        elif self.sast.status == "none":
            self.add_install(help=self.help_messages["install"])
        else:
            raise Exception(f"Invalid status {self.sast.status} for {self.sast.name}")

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

    def add_install(self: Self, help: str = "") -> None:
        """Add the 'install' command to the CLI.

        This command opens the tool's installation guide URL in a web browser.

        Args:
            help: The help string for the command.

        """

        @self.cli.command(help=help)
        def install() -> None:
            """Display installation instructions for missing requirements."""
            from rich.panel import Panel

            install_help = ""
            sast_reqs = self.sast.requirements
            missing_reqs = sast_reqs.get_missing()
            for req in sast_reqs.full + sast_reqs.partial:
                install_help += (
                    f"{'❌' if req in missing_reqs else '✅'} [b]{req}[/b]\n"
                )
                if req.depends_on:
                    install_help += f"- Depends on: [red]{', '.join([str(r) for r in req.depends_on])}[/red]\n"
                elif req.instruction:
                    install_help += f"- Instruction: [red]{req.instruction}[/red]\n"
                if req.url:
                    install_help += f"- URL: [u]{req.url}[/u]\n"
                install_help += "\n"
            install_help.strip("\n")
            panel = Panel(
                install_help,
                title=f"{self.sast.name} requirements",
                expand=False,
            )
            print(panel)

    def add_analyze(self: Self, help: str = "") -> None:
        """Add the 'analyze' command to the CLI.

        This command runs the SAST tool on the current directory.

        Args:
            help: The help string for the command.

        """
        # PrebuiltSAST additional options
        if isinstance(self.sast, PrebuiltBuildlessSAST):
            artifacts_default = typer.Option(
                default=None,
                help=f"Pre-built artifacts ({self.sast.artefact_name} {self.sast.artefact_type}) for more accurate analysis",
                metavar="ARTIFACTS",
            )
        elif isinstance(self.sast, PrebuiltSAST):
            artifacts_default = typer.Option(
                help=f"Pre-built artifacts ({self.sast.artefact_name} {self.sast.artefact_type})",
                metavar="ARTIFACTS",
            )
        else:
            artifacts_default = typer.Option(
                default=None,
                hidden=True,
                help="Pre-built artifacts (for PrebuiltSAST only)",
                metavar="ARTIFACTS",
            )

        @self.cli.command(help=help)
        def analyze(
            lang: Annotated[
                str,
                typer.Argument(
                    click_type=Choice(self.sast.supported_languages),
                    help="Source code language (only one at the time)",
                    metavar="LANG",
                ),
            ],
            # Additional REQUIRED options
            artifacts: Optional[Path] = artifacts_default,
            # Common NOT REQUIRED option
            overwrite: Annotated[
                bool,
                typer.Option(
                    "--overwrite",
                    help="Overwrite existing analysis results for current project",
                ),
            ] = False,
        ) -> None:
            """Run SAST analysis on the project in the current working directory.

            Args:
                lang: The source code language to analyze.
                artifacts: The path to pre-built artifacts, required for PrebuiltSAST tools.
                overwrite: If True, overwrite any existing analysis results for the project.

            """
            if isinstance(self.sast, PrebuiltBuildlessSAST) and artifacts is None:
                print(
                    f"[i]{self.sast.name} can use pre-built artifacts ({self.sast.artefact_name} {self.sast.artefact_type}) for more accurate analysis"
                )
                print("[i]Use the flag --artifacts to provide the artifacts")

            output_dir = self.sast.output_dir / Path.cwd().name
            if output_dir.is_dir():
                if overwrite:
                    shutil.rmtree(output_dir)
                    self.sast.run_analysis(
                        lang, Path.cwd(), output_dir, artifacts=artifacts
                    )
                else:
                    print(f"Found existing analysis result at {output_dir}")
                    print("Use --overwrite to overwrite it")
            else:
                self.sast.run_analysis(
                    lang, Path.cwd(), output_dir, artifacts=artifacts
                )

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
                    click_type=Choice(self.sast.supported_dataset_full_names),
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
            """Run a SAST benchmark against a selected dataset.

            Args:
                dataset: The name of the dataset to use for benchmarking
                    (e.g., "BenchmarkJava_java").
                overwrite: If True, overwrite existing benchmark results.
                testing: If True, run benchmark over a single dataset unit for testing.

            """
            dataset_name, lang = dataset.split("_")
            dataset = DATASETS_ALL[dataset_name](lang)
            if isinstance(dataset, FileDataset):
                self.sast.analyze_files(dataset, overwrite, testing)
            elif isinstance(dataset, GitRepoDataset):
                self.sast.analyze_repos(dataset, overwrite, testing)

    ## Parser
    def add_list(self, help: str = "") -> None:
        """Add the 'list' command to the CLI.

        This command lists all available analysis results for the SAST tool.

        Args:
            help: The help string for the command.

        """

        @self.cli.command(help=help)
        def list() -> None:
            """List available analysis results."""
            from rich.table import Table

            table = Table(show_lines=True)
            table.add_column("Name", justify="center", no_wrap=True)
            table.add_column("Type", justify="center", no_wrap=True)
            table.add_column("Result directory", justify="center", no_wrap=True)

            for dataset_full_name in self.sast.list_results(dataset=True):
                table.add_row(
                    dataset_full_name,
                    "Dataset",
                    str(self.sast.output_dir / dataset_full_name),
                )
            for project in self.sast.list_results(project=True):
                table.add_row(project, "Project", str(self.sast.output_dir / project))

            print(table)

    # Graphics
    def add_plot(self, help: str = "") -> None:
        """Add the 'plot' command to the CLI.

        This command generates visualizations from analysis or benchmark results.

        Args:
            help: The help string for the command.

        """

        @self.cli.command(help=help)
        def plot(
            result: Annotated[
                str,
                typer.Argument(
                    click_type=Choice(
                        self.sast.list_results(project=True, dataset=True)
                    ),
                    metavar="RESULT",
                ),
            ],
            overwrite: Annotated[
                bool,
                typer.Option(
                    "--overwrite",
                    help="Overwrite existing figures",
                ),
            ] = False,
            format: Annotated[
                Literal["png", "pdf", "svg"],
                typer.Option("--format", help="Figures export format"),
            ] = "png",
        ) -> None:
            """Generate and export plots for a given project or dataset result."""
            from codesectools.sasts.core.graphics import (
                FileDatasetGraphics,
                GitRepoDatasetGraphics,
                ProjectGraphics,
            )

            if result in self.sast.list_results(project=True):
                project = result
                project_graphics = ProjectGraphics(self.sast, project_name=project)
                project_graphics.export(overwrite=overwrite, format=format)
            elif result in self.sast.list_results(dataset=True):
                dataset = result
                dataset_name, lang = dataset.split("_")
                dataset = DATASETS_ALL[dataset_name](lang)
                if isinstance(dataset, FileDataset):
                    file_dataset_graphics = FileDatasetGraphics(
                        self.sast, dataset=dataset
                    )
                    file_dataset_graphics.export(overwrite=overwrite, format=format)
                elif isinstance(dataset, GitRepoDataset):
                    git_repo_dataset_graphics = GitRepoDatasetGraphics(
                        self.sast, dataset=dataset
                    )
                    git_repo_dataset_graphics.export(overwrite=overwrite, format=format)
                else:
                    print("Not supported yet")
