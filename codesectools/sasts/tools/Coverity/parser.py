"""Provide a base parser for SAST tools that output in SARIF format."""

import json
from pathlib import Path
from typing import Self

from codesectools.sasts.core.parser import AnalysisResult, Defect
from codesectools.sasts.core.parser.format.CoverityJsonOutputV10 import (
    CoverityJsonOutputV10,
)
from codesectools.sasts.core.sast import AnalysisInfo
from codesectools.shared.cwe import CWEs
from codesectools.utils import MissingFile


class CoverityAnalysisResult(AnalysisResult):
    """Represent the complete result of a Coverity analysis."""

    sast_name = "Coverity"
    impact_level_mapping = {
        "High": "error",
        "Medium": "warning",
        "Low": "note",
        "Audit": "none",
    }

    def __init__(
        self, output_dir: Path, coverity_dict: dict, analysis_info: AnalysisInfo
    ) -> None:
        """Initialize a CoverityAnalysisResult instance.

        Args:
            output_dir: The directory containing the analysis output.
            coverity_dict: The parsed Coverity JSON dictionary.
            analysis_info: The analysis metadata.

        """
        super().__init__(
            name=output_dir.name,
            source_path=Path(analysis_info.project_dir),
            lang=analysis_info.lang,
            defects=[],
            time=analysis_info.duration,
            lines_of_codes=analysis_info.lines_of_codes,
        )

        self.output_dir = output_dir
        self.cov_json = CoverityJsonOutputV10.model_validate(coverity_dict)
        self.issues = self.cov_json.issues

        for issue in self.issues:
            if issue.language:
                if issue.language.lower() != self.lang:
                    continue
            else:
                continue

            checker = issue.checker_name
            filepath = Path(issue.main_event_file_pathname)
            lines = [issue.main_event_line_number]
            event_descriptions = []

            for event in issue.events:
                event_descriptions.append(
                    f"L{event.line_number}: {event.event_description}"
                )

            if cwe_str := issue.checker_properties.cwe_category:
                cwe = CWEs.from_id(int(cwe_str))
            else:
                cwe = CWEs.NOCWE
            message = "\n".join(
                [issue.checker_properties.subcategory_long_description]
                + event_descriptions
            )
            level = self.impact_level_mapping[issue.checker_properties.impact]

            self.defects.append(
                Defect(
                    sast_name=self.sast_name,
                    filepath=filepath,
                    checker=checker,
                    level=level,  # ty:ignore[invalid-argument-type]
                    cwe=cwe,
                    message=message,
                    lines=lines,
                )
            )

    @classmethod
    def load_from_output_dir(cls, output_dir: Path) -> Self:
        """Load and parse a SARIF report from an output directory."""
        # Analysis Info
        analysis_info = AnalysisInfo.model_validate_json(
            (output_dir / "codesectools.json").read_text()
        )

        # Analysis outputs
        coveirty_report_path = output_dir / "coverity.json"
        if coveirty_report_path.is_file():
            coverity_dict = json.load(coveirty_report_path.open())
        else:
            raise MissingFile([str(coveirty_report_path)])

        return cls(output_dir, coverity_dict, analysis_info)
