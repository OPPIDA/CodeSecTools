"""Defines the command-line interface for running all available SAST tools."""

import io
import shutil
from hashlib import sha256
from pathlib import Path

import typer
from click import Choice
from rich import print
from typing_extensions import Annotated, Literal

from codesectools.datasets import DATASETS_ALL
from codesectools.datasets.core.dataset import FileDataset, GitRepoDataset
from codesectools.sasts import SASTS_ALL
from codesectools.sasts.all.sast import AllSAST
from codesectools.sasts.core.sast import PrebuiltBuildlessSAST, PrebuiltSAST
from codesectools.utils import group_successive, shorten_path


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
        """Run analysis on the current project with all available SAST tools."""
        for sast in all_sast.sasts_by_lang.get(lang, []):
            if isinstance(sast, PrebuiltBuildlessSAST) and artifacts is None:
                print(
                    f"[i]{sast.name} can use pre-built artifacts ({sast.artefact_name} {sast.artefact_type}) for more accurate analysis"
                )
                print("[i]Use the flag --artifacts to provide the artifacts")
            elif isinstance(sast, PrebuiltSAST) and artifacts is None:
                print(
                    f"[b]Skipping {sast.name} because it requires pre-built artifacts ({sast.artefact_name} {sast.artefact_type})"
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
        """Run a benchmark on a dataset using all available SAST tools."""
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
        """Generate and display plots for a project's aggregated analysis results."""
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
        """Generate an HTML report for a project's aggregated analysis results."""
        from rich.console import Console
        from rich.style import Style
        from rich.syntax import Syntax
        from rich.table import Table
        from rich.text import Text

        report_dir = all_sast.output_dir / project / "report"
        if report_dir.is_dir():
            if overwrite:
                shutil.rmtree(report_dir)
            else:
                print(f"Found existing report for {project} at {report_dir}")
                print("Use --overwrite to overwrite it")
                raise typer.Exit()

        report_dir.mkdir(parents=True)

        result = all_sast.parser.load_from_output_dir(project_name=project)
        report_data = result.prepare_report_data()

        template = """
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="UTF-8">
    <style>
    {stylesheet}
    body {{
        color: {foreground};
        background-color: {background};
        font-family: Menlo, 'DejaVu Sans Mono', consolas, 'Courier New', monospace;
    }}
    .tippy-box {{
        background-color: white;
        color: black;
    }}
    img {{
        display: block;
        margin: auto;
        border: solid black 1px;
    }}
    #top {{
        position: fixed;
        bottom: 20px;
        right: 30px;
        background-color: white;
        padding: 10px;
        border: solid black 5px;
    }}
    </style>
    </head>
    <body>
        <a href="./home.html"><h1>CodeSecTools All SAST Tools Report</h1></a>
        <h3>SAST Tools used: [sasts]</h3>
        <h2>[name]</h2>
        <pre style="font-family:Menlo,'DejaVu Sans Mono',consolas,'Courier New',monospace"><code style="font-family:inherit">{code}</code></pre>
        <script src="https://unpkg.com/@popperjs/core@2"></script>
        <script src="https://unpkg.com/tippy.js@6"></script>
        <script>[tippy_calls]</script>
        <a href="#" id="top">^</a>
    </body>
    </html>
    """
        template = template.replace(
            "[sasts]", ", ".join(sast_name for sast_name in result.sast_names)
        )

        home_page = Console(record=True, file=io.StringIO())

        main_table = Table(title="")
        main_table.add_column("Files (sorted by defect number)")

        for defect_data in report_data["defects"].values():
            defect_report_name = (
                f"{sha256(defect_data['source_path'].encode()).hexdigest()}.html"
            )
            defect_page = Console(record=True, file=io.StringIO())

            # Defect stat table
            defect_stats_table = Table(title="")
            for key in list(report_data["defects"].values())[0]["score"].keys():
                defect_stats_table.add_column(
                    key.replace("_", " ").title(), justify="center"
                )
            defect_stats_table.add_row(*[str(v) for v in defect_data["score"].values()])
            defect_page.print(defect_stats_table)

            defect_report_redirect = Text(
                shorten_path(defect_data["source_path"], 60),
                style=Style(link=defect_report_name),
            )
            main_table.add_row(defect_report_redirect)

            # Defect table
            defect_table = Table(title="", show_lines=True)
            defect_table.add_column("Location", justify="center")
            defect_table.add_column("SAST", justify="center")
            defect_table.add_column("CWE", justify="center")
            defect_table.add_column("Message")
            rows = []
            for defect in defect_data["raw"]:
                groups = group_successive(defect.lines)
                if groups:
                    for group in groups:
                        start, end = group[0], group[-1]
                        shortcut = Text(f"{start}", style=Style(link=f"#L{start}"))
                        cwe_link = (
                            Text(
                                f"CWE-{defect.cwe.id}",
                                style=Style(
                                    link=f"https://cwe.mitre.org/data/definitions/{defect.cwe.id}.html"
                                ),
                            )
                            if defect.cwe.id != -1
                            else "None"
                        )
                        rows.append(
                            (start, shortcut, defect.sast, cwe_link, defect.message)
                        )
                else:
                    cwe_link = (
                        Text(
                            f"CWE-{defect.cwe.id}",
                            style=Style(
                                link=f"https://cwe.mitre.org/data/definitions/{defect.cwe.id}.html"
                            ),
                        )
                        if defect.cwe.id != -1
                        else "None"
                    )
                    rows.append(
                        (float("inf"), "None", defect.sast, cwe_link, defect.message)
                    )

            for row in sorted(rows, key=lambda r: r[0]):
                defect_table.add_row(*row[1:])
            defect_page.print(defect_table)

            # Syntax
            if not Path(defect_data["source_path"]).is_file():
                tippy_calls = ""
                print(
                    f"Source file {defect_data['source_path']} not found, skipping it..."
                )
            else:
                syntax = Syntax.from_path(defect_data["source_path"], line_numbers=True)
                tooltips = {}
                highlights = {}
                for location in defect_data["locations"]:
                    sast, cwe, message, (start, end) = location
                    for i in range(start, end + 1):
                        text = (
                            f"<b>{sast}</b>: <i>{message} (CWE-{cwe.id})</i>"
                            if cwe.id != -1
                            else f"<b>{sast}</b>: <i>{message}</i>"
                        )
                        if highlights.get(i):
                            highlights[i].add(text)
                        else:
                            highlights[i] = {text}

                for line, texts in highlights.items():
                    element_id = f"L{line}"
                    bgcolor = "red" if len(texts) > 1 else "yellow"
                    syntax.stylize_range(
                        Style(bgcolor=bgcolor, link=f"HACK{element_id}"),
                        start=(line, 0),
                        end=(line + 1, 0),
                    )
                    tooltips[element_id] = "<hr>".join(text for text in texts)

                tippy_calls = ""
                for element_id, content in tooltips.items():
                    tippy_calls += f"""tippy('#{element_id}', {{ content: `{content.replace("`", "\\`")}`, allowHTML: true, interactive: true }});\n"""

                defect_page.print(syntax)

            html_content = defect_page.export_html(code_format=template)
            html_content = html_content.replace('href="HACK', 'id="')
            html_content = html_content.replace("[name]", defect_data["source_path"])
            html_content = html_content.replace("[tippy_calls]", tippy_calls)

            report_defect_file = report_dir / defect_report_name
            report_defect_file.write_text(html_content)

        home_page.print(main_table)
        html_content = home_page.export_html(code_format=template)
        html_content = html_content.replace("[name]", f"Project: {project}")

        report_home_file = report_dir / "home.html"
        report_home_file.write_text(html_content)

        print(f"Report generated at {report_dir.resolve()}")

    return cli
