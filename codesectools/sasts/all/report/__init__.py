"""Defines the base report generation functionality for aggregated SAST results."""

from abc import ABC, abstractmethod

from codesectools.sasts.all.sast import AllSAST


class Report(ABC):
    """Abstract base class for report generation.

    Attributes:
        format (str): The format of the report (e.g., "HTML", "SARIF").
        project (str): The name of the project.
        all_sast (AllSAST): The AllSAST manager instance.
        report_dir (Path): The directory where reports are saved.
        result (AllSASTAnalysisResult): The parsed analysis results.
        report_data (dict): The data prepared for rendering the report.

    """

    format: str

    def __init__(self, project: str, all_sast: AllSAST, top: int | None = None) -> None:
        """Initialize the Report.

        Args:
            project: The name of the project.
            all_sast: The AllSAST instance.
            top: The number of top files to include in the report based on score.

        """
        self.project = project
        self.all_sast = all_sast
        self.report_dir = all_sast.output_dir / project / "report" / self.format

        self.result = all_sast.parser.load_from_output_dir(project_name=project)
        self.report_data = self.result.prepare_report_data(top=top)

    @abstractmethod
    def generate(self) -> None:
        """Generate the report."""
        pass
