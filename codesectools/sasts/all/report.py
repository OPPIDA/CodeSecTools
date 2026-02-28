"""Generates HTML reports for aggregated SAST analysis results."""

import io
from hashlib import sha256
from pathlib import Path

from codesectools.sasts.all.sast import AllSAST
from codesectools.utils import group_successive


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

    def generate_single_defect(self, defect_file: dict) -> str:
        """Generate the HTML report for a single file with defects."""
        from rich.console import Console
        from rich.style import Style
        from rich.syntax import Syntax
        from rich.table import Table
        from rich.text import Text

        file_page = Console(record=True, file=io.StringIO())

        file_page.print(f"Score: {defect_file['score']:.2f}")

        # Defect table
        defect_table = Table(title="", show_lines=True)
        defect_table.add_column("Location", justify="center")
        defect_table.add_column("SAST", justify="center")
        defect_table.add_column("CWE", justify="center")
        defect_table.add_column("Message")
        rows = []
        for defect in defect_file["defects"]:
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
                        (start, shortcut, defect.sast_name, cwe_link, defect.message)
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
        if not Path(defect_file["source_path"]).is_file():
            tippy_calls = ""
            print(f"Source file {defect_file['source_path']} not found, skipping it...")
        else:
            syntax = Syntax.from_path(defect_file["source_path"], line_numbers=True)
            tooltips = {}
            highlights = {}
            for location in defect_file["locations"]:
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
        html_content = html_content.replace("[name]", defect_file["source_path"])
        html_content = html_content.replace("[tippy_calls]", tippy_calls)

        return html_content

    def generate(self) -> None:
        """Generate the HTML report.

        Creates the report directory and generates HTML files for the main view
        and for each file with defects.
        """
        from rich.console import Console
        from rich.progress import track
        from rich.style import Style
        from rich.table import Table
        from rich.text import Text

        self.TEMPLATE = self.TEMPLATE.replace(
            "[sasts]", ", ".join(sast_name for sast_name in self.result.sast_names)
        )

        home_page = Console(record=True, file=io.StringIO())

        main_table = Table(title="")
        main_table.add_column("Score", justify="center")
        main_table.add_column("Files")

        for defect_file in track(
            self.report_data.values(),
            description="Generating report for source file with defects...",
        ):
            html_content = self.generate_single_defect(defect_file)
            file_report_name = (
                f"{sha256(defect_file['source_path'].encode()).hexdigest()}.html"
            )
            file_report_redirect = Text(
                str(
                    Path(defect_file["source_path"]).relative_to(
                        self.result.source_path
                    )  # ty:ignore[no-matching-overload]
                ),
                style=Style(link=file_report_name),
            )

            report_file = self.report_dir / file_report_name
            report_file.write_text(html_content)

            main_table.add_row(
                Text(f"{defect_file['score']:.2f}"), file_report_redirect
            )

        home_page.print(main_table)
        html_content = home_page.export_html(code_format=self.TEMPLATE)
        html_content = html_content.replace(
            "[name]", f"Project: {self.result.source_path}"
        )

        report_home_file = self.report_dir / "home.html"
        report_home_file.write_text(html_content)
