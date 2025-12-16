"""Defines the command-line interface for running all available SAST tools."""

import shutil
from pathlib import Path

import typer
from click import Choice
from rich import print
from typing_extensions import Annotated, Literal

from codesectools.datasets import DATASETS_ALL
from codesectools.datasets.core.dataset import FileDataset, GitRepoDataset
from codesectools.sasts import SASTS_ALL
from codesectools.sasts.all.report import ReportEngine
from codesectools.sasts.all.sast import AllSAST
from codesectools.sasts.core.sast import PrebuiltBuildlessSAST, PrebuiltSAST


def build_cli() -> typer.Typer:
    """Build the Typer CLI for running all SAST tools."""
    cli = typer.Typer(name="allsast", no_args_is_help=True)
    all_sast = AllSAST()

    @cli.callback()
    def main() -> None:
        """Run all available SAST tools together."""
        pass

    @cli.command(help="List used SAST tools.")
    def info() -> None:
        """Display the status of all SAST tools and their inclusion in AllSAST."""
        from rich.table import Table

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

    @cli.command(help="Analyze a project using all availbale SAST tools.")
    def analyze(
        lang: Annotated[
            str,
            typer.Argument(
                click_type=Choice(all_sast.sasts_by_lang.keys()),
                help="Source code language (only one at the time)",
                metavar="LANG",
            ),
        ],
        # Additional options
        artifacts: Annotated[
            Path | None,
            typer.Option(
                help="Pre-built artifacts directory (for PrebuiltSAST only)",
                metavar="ARTIFACTS",
            ),
        ] = None,
        # Common NOT REQUIRED option
        overwrite: Annotated[
            bool,
            typer.Option(
                "--overwrite",
                help="Overwrite existing analysis results for current project",
            ),
        ] = False,
    ) -> None:
        """Run analysis on the current project with all available SAST tools.

        Args:
            lang: The source code language to analyze.
            artifacts: The path to pre-built artifacts (for PrebuiltSAST only).
            overwrite: If True, overwrite existing analysis results for the current project.

        """
        for sast in all_sast.sasts_by_lang.get(lang, []):
            if isinstance(sast, PrebuiltBuildlessSAST) and artifacts is None:
                print(
                    f"[i]{sast.name} can use pre-built artifacts ({sast.artifact_name} {sast.artifact_type}) for more accurate analysis"
                )
                print("[i]Use the flag --artifacts to provide the artifacts")
            elif isinstance(sast, PrebuiltSAST) and artifacts is None:
                print(
                    f"[b]Skipping {sast.name} because it requires pre-built artifacts ({sast.artifact_name} {sast.artifact_type})"
                )
                print("[b]Use the flag --artifacts to provide the artifacts")
                continue

            output_dir = sast.output_dir / Path.cwd().name
            if output_dir.is_dir():
                if overwrite:
                    shutil.rmtree(output_dir)
                    sast.run_analysis(lang, Path.cwd(), output_dir, artifacts=artifacts)
                else:
                    print(f"Found existing analysis result at {output_dir}")
                    print("Use --overwrite to overwrite it")
            else:
                sast.run_analysis(lang, Path.cwd(), output_dir, artifacts=artifacts)

    @cli.command(help="Benchmark a dataset using all SAST tools.")
    def benchmark(
        dataset: Annotated[
            str,
            typer.Argument(
                click_type=Choice(
                    [
                        f"{d.name}_{lang}"
                        for d in all_sast.sasts_by_dataset
                        for lang in d.supported_languages
                    ]
                ),
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
        """Run a benchmark on a dataset using all available SAST tools.

        Args:
            dataset: The name of the dataset to benchmark.
            overwrite: If True, overwrite existing results.
            testing: If True, run benchmark over a single dataset unit for testing.

        """
        dataset_name, lang = dataset.split("_")
        for sast in all_sast.sasts_by_dataset.get(DATASETS_ALL[dataset_name], []):
            dataset = DATASETS_ALL[dataset_name](lang)
            if isinstance(dataset, FileDataset):
                sast.analyze_files(dataset, overwrite, testing)
            elif isinstance(dataset, GitRepoDataset):
                sast.analyze_repos(dataset, overwrite, testing)

    @cli.command(name="list", help="List existing analysis results.")
    def list_() -> None:
        """List existing analysis results for projects and datasets."""
        from rich.table import Table

        table = Table(show_lines=True)
        table.add_column("Name", justify="center", no_wrap=True)
        table.add_column("Type", justify="center", no_wrap=True)
        table.add_column("Analyzed with", justify="center", no_wrap=True)

        for dataset_full_name in all_sast.list_results(dataset=True):
            table.add_row(
                dataset_full_name,
                "Dataset",
                ", ".join(
                    f"[b]{sast.name}[/b]"
                    for sast in all_sast.sasts
                    if dataset_full_name in sast.list_results(dataset=True)
                ),
            )
        for project in all_sast.list_results(project=True):
            table.add_row(
                project,
                "Project",
                ", ".join(
                    f"[b]{sast.name}[/b]"
                    for sast in all_sast.sasts
                    if project in sast.list_results(project=True)
                ),
            )

        print(table)

    @cli.command(
        help="Generate plot for results visualization (datasets are not supported)."
    )
    def plot(
        project: Annotated[
            str,
            typer.Argument(
                click_type=Choice(all_sast.list_results(project=True)),
                metavar="PROJECT",
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
        """Generate and display plots for a project's aggregated analysis results.

        Args:
            project: The name of the project to visualize.
            overwrite: If True, overwrite existing figures.
            format: The export format for the figures.

        """
        from codesectools.sasts.all.graphics import ProjectGraphics

        project_graphics = ProjectGraphics(project_name=project)
        project_graphics.export(overwrite=overwrite, format=format)

    @cli.command(help="Generate an HTML report")
    def report(
        project: Annotated[
            str,
            typer.Argument(
                click_type=Choice(all_sast.list_results(project=True)),
                metavar="PROJECT",
            ),
        ],
        overwrite: Annotated[
            bool,
            typer.Option(
                "--overwrite",
                help="Overwrite existing results",
            ),
        ] = False,
    ) -> None:
        """Generate an HTML report for a project's aggregated analysis results.

        Args:
            project: The name of the project to report on.
            overwrite: If True, overwrite existing results.

        """
        report_dir = all_sast.output_dir / project / "report"
        if report_dir.is_dir():
            if overwrite:
                shutil.rmtree(report_dir)
            else:
                print(f"Found existing report for {project} at {report_dir}")
                print("Use --overwrite to overwrite it")
                raise typer.Exit()

        report_dir.mkdir(parents=True)

        report_engine = ReportEngine(project=project, all_sast=all_sast)
        report_engine.generate()
        print(f"Report generated at {report_dir.resolve()}")

    return cli
