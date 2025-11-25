"""Generates HTML reports for aggregated SAST analysis results."""

import io
from hashlib import sha256
from pathlib import Path

from rich import print

from codesectools.sasts.all.sast import AllSAST
from codesectools.utils import group_successive, shorten_path


class ReportEngine:
    """Generate interactive HTML reports for SAST analysis results.

    Attributes:
        TEMPLATE (str): The HTML template used for report generation.
        project (str): The name of the project.
        all_sast (AllSAST): The AllSAST manager instance.
        report_dir (Path): The directory where reports are saved.
        result (AllSASTAnalysisResult): The parsed analysis results.
        report_data (dict): The data prepared for rendering the report.

    """

    TEMPLATE = """
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

    def __init__(self, project: str, all_sast: AllSAST) -> None:
        """Initialize the ReportEngine.

        Args:
            project: The name of the project.
            all_sast: The AllSAST instance.

        """
        self.project = project
        self.all_sast = all_sast
        self.report_dir = all_sast.output_dir / project / "report"

        self.result = all_sast.parser.load_from_output_dir(project_name=project)
        self.report_data = self.result.prepare_report_data()

    def generate_single_defect(self, file_data: dict) -> tuple:
        """Generate the HTML report for a single file with defects."""
        from rich.console import Console
        from rich.style import Style
        from rich.syntax import Syntax
        from rich.table import Table
        from rich.text import Text

        file_report_name = (
            f"{sha256(file_data['source_path'].encode()).hexdigest()}.html"
        )
        file_page = Console(record=True, file=io.StringIO())

        # Defect stat table
        file_stats_table = Table(title="")
        for key in list(self.report_data["files"].values())[0]["count"].keys():
            file_stats_table.add_column(key.replace("_", " ").title(), justify="center")

        rendered_scores = []
        for v in file_data["count"].values():
            if isinstance(v, float):
                rendered_scores.append(f"~{v}")
            else:
                rendered_scores.append(str(v))

        file_stats_table.add_row(*rendered_scores)
        file_page.print(file_stats_table)

        file_report_redirect = Text(
            shorten_path(file_data["source_path"], 60),
            style=Style(link=file_report_name),
        )

        # Defect table
        defect_table = Table(title="", show_lines=True)
        defect_table.add_column("Location", justify="center")
        defect_table.add_column("SAST", justify="center")
        defect_table.add_column("CWE", justify="center")
        defect_table.add_column("Message")
        rows = []
        for defect in file_data["defects"]:
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
        file_page.print(defect_table)

        # Syntax
        if not Path(file_data["source_path"]).is_file():
            tippy_calls = ""
            print(f"Source file {file_data['source_path']} not found, skipping it...")
        else:
            syntax = Syntax.from_path(file_data["source_path"], line_numbers=True)
            tooltips = {}
            highlights = {}
            for location in file_data["locations"]:
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

            file_page.print(syntax)

        html_content = file_page.export_html(code_format=self.TEMPLATE)
        html_content = html_content.replace('href="HACK', 'id="')
        html_content = html_content.replace("[name]", file_data["source_path"])
        html_content = html_content.replace("[tippy_calls]", tippy_calls)

        report_file = self.report_dir / file_report_name
        report_file.write_text(html_content)

        return file_report_redirect, rendered_scores

    def generate(self) -> None:
        """Generate the HTML report.

        Creates the report directory and generates HTML files for the main view
        and for each file with defects.
        """
        from rich.console import Console
        from rich.progress import track
        from rich.table import Table

        self.TEMPLATE = self.TEMPLATE.replace(
            "[sasts]", ", ".join(sast_name for sast_name in self.result.sast_names)
        )

        home_page = Console(record=True, file=io.StringIO())

        main_table = Table(title="")
        main_table.add_column("Files")
        for key in list(self.report_data["files"].values())[0]["score"].keys():
            main_table.add_column(
                key.replace("_", " ").title(), justify="center", no_wrap=True
            )

        for file_data in track(
            self.report_data["files"].values(),
            description="Generating report for source file with defects...",
        ):
            file_report_redirect, rendered_scores = self.generate_single_defect(
                file_data
            )
            main_table.add_row(file_report_redirect, *rendered_scores)

        home_page.print(main_table)
        html_content = home_page.export_html(code_format=self.TEMPLATE)
        html_content = html_content.replace("[name]", f"Project: {self.project}")

        report_home_file = self.report_dir / "home.html"
        report_home_file.write_text(html_content)
