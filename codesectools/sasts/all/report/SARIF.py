"""Generates SARIF reports for aggregated SAST analysis results."""

from typing import Optional

from codesectools.sasts.all.report import Report
from codesectools.sasts.core.parser.format.SARIF import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    Region,
    ReportingDescriptor,
    Result,
    Run,
    Tool,
    ToolComponent,
)
from codesectools.sasts.core.parser.format.SARIF import (
    StaticAnalysisResultsFormatSarifVersion210JsonSchema as SARIF,
)


class SARIFReport(Report):
    """Generate SARIF reports for SAST analysis results.

    Attributes:
        format (str): The format of the report, which is "SARIF".
        project (str): The name of the project.
        all_sast (AllSAST): The AllSAST manager instance.
        report_dir (Path): The directory where reports are saved.
        result (AllSASTAnalysisResult): The parsed analysis results.
        report_data (dict): The data prepared for rendering the report.

    """

    format = "SARIF"

    def generate(self) -> None:
        """Generate the SARIF report."""
        included_defect_file = self.report_data.keys()

        runs: list[Run] = []
        for analysis_result in self.result.analysis_results.values():
            results: list[Result] = []
            rules: list[ReportingDescriptor] = []
            rule_ids = set()

            for defect in analysis_result.defects:
                if defect.filepath_str not in included_defect_file:
                    continue

                relative_uri = defect.filepath.relative_to(
                    analysis_result.source_path
                ).as_posix()

                region: Optional[Region] = None
                if defect.lines:
                    start_line_num = min(defect.lines)
                    end_line_num = (
                        max(defect.lines) if len(defect.lines) > 1 else start_line_num
                    )

                    region = Region(start_line=start_line_num, end_line=end_line_num)

                physical_location = PhysicalLocation(
                    artifact_location=ArtifactLocation(
                        uri=relative_uri, uri_base_id="%SRCROOT%"
                    ),
                    region=region,
                )

                result = Result(
                    rule_id=defect.checker,
                    level=defect.level,
                    message=Message(text=defect.message),
                    locations=[Location(physical_location=physical_location)],  # ty:ignore[missing-argument]
                    properties=PropertyBag(
                        __root__={"cwe": str(defect.cwe)}  # ty:ignore[unknown-argument]
                    ),
                )  # ty:ignore[missing-argument]
                results.append(result)

                if defect.checker not in rule_ids:
                    rules.append(ReportingDescriptor(id=defect.checker))  # ty:ignore[missing-argument]
                    rule_ids.add(defect.checker)

            tool = Tool(
                driver=ToolComponent(
                    name=analysis_result.sast_name,
                    rules=rules,
                )  # ty:ignore[missing-argument]
            )  # ty:ignore[missing-argument]

            run = Run(
                tool=tool,
                results=results,
                original_uri_base_ids={
                    "%SRCROOT%": ArtifactLocation(
                        uri=analysis_result.source_path.resolve().as_uri()
                    )
                },
                properties=PropertyBag(
                    __root__={
                        "lines_of_codes": analysis_result.lines_of_codes,
                        "analysis_time_seconds": analysis_result.time,
                        "language": analysis_result.lang,
                    }  # ty:ignore[unknown-argument]
                ),
            )  # ty:ignore[missing-argument]

            runs.append(run)

        sarif_report = SARIF(
            version="2.1.0",
            runs=runs,
        )

        sarif_file = (self.report_dir / self.result.name).with_suffix(".sarif")
        sarif_file.write_text(
            sarif_report.model_dump_json(by_alias=True, exclude_none=True, indent=2)
        )
