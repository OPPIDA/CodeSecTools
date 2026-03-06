"""Provide a base parser for SAST tools that output in SARIF format."""

import json
from abc import abstractmethod
from pathlib import Path
from typing import Self

from codesectools.sasts.core.parser import AnalysisResult, Defect
from codesectools.sasts.core.parser.format.SARIF import (
    PropertyBag,
    ReportingDescriptor,
    Result,
)
from codesectools.sasts.core.parser.format.SARIF import (
    StaticAnalysisResultsFormatSarifVersion210JsonSchema as SARIF,
)
from codesectools.sasts.core.sast import AnalysisInfo
from codesectools.shared.cwe import CWE
from codesectools.utils import MissingFile


class SARIFAnalysisResult(AnalysisResult):
    """Abstract base class for parsing SARIF formatted analysis results."""

    def __init__(
        self, output_dir: Path, sarif_dict: dict, analysis_info: AnalysisInfo
    ) -> None:
        """Initialize the SARIFAnalysisResult.

        Args:
            output_dir: The directory containing the analysis output.
            sarif_dict: The raw SARIF data as a dictionary.
            analysis_info: Metadata about the analysis run.

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
        self.sarif_dict = self.patch_dict(sarif_dict.copy())

        self.sarif = SARIF.model_validate(self.sarif_dict)
        self.run = self.sarif.runs[0]
        self.rules = self.get_rules()
        self.raw_rules = self.get_raw_rules()
        self.results = self.run.results or []

        for result in self.results:
            filepath, lines = self.get_location(result)

            if not filepath:
                continue

            if rule_id := result.rule_id:
                rule = self.rules[rule_id]

                if rule.default_configuration:
                    level = rule.default_configuration.level or "none"
                if result.level:
                    level = result.level or "none"
                else:
                    level = "none"

                cwe = self.get_cwe(result, rule_id)
            else:
                continue

            message = result.message.root.text or ""

            self.defects.append(
                Defect(
                    sast_name=self.sast_name,
                    filepath=filepath,
                    checker=rule_id,
                    level=level,
                    cwe=cwe,
                    message=message,
                    lines=lines,
                )
            )

    def patch_dict(self, sarif_dict: dict) -> dict:
        """Patch the SARIF dictionary to fix common issues before parsing."""
        return sarif_dict

    def save_patched_dict(self, patched_dict: dict) -> None:
        """Save the patched dictionary to a file for debugging."""
        json.dump(
            patched_dict,
            (self.output_dir / f"{self.sast_name.lower()}_patched.sarif").open("w"),
        )

    def get_rules(self) -> dict[str, ReportingDescriptor]:
        """Extract and return all rule descriptors from the SARIF data."""
        rules = {}
        if self.run.tool.driver.rules:
            for rule in self.run.tool.driver.rules:
                if rule:
                    rules[rule.id] = rule
        return rules

    @staticmethod
    def get_raw_rules() -> dict:
        """Get the raw rule definitions, often from a non-SARIF source."""
        return {}

    def get_rule_properties(self, rule_id: str) -> PropertyBag | None:
        """Get the properties for a specific rule ID."""
        if rule := self.rules[rule_id]:
            if properties := rule.properties:
                return properties
        return None

    def get_location(self, result: Result) -> tuple[Path | None, list[int]]:
        """Extract the file path and line numbers from a SARIF result."""
        filepath = None
        lines = []
        if result.locations:
            if physical_location := result.locations[0].physical_location:
                if root := physical_location.root:
                    if artifact_location := root.artifact_location:
                        if uri := artifact_location.uri:
                            filepath = Path(uri)

                    if region := root.region:
                        lines = [
                            line
                            for line in [region.start_line, region.end_line]
                            if line
                        ]

        return filepath, lines

    @abstractmethod
    def get_cwe(self, result: Result, rule_id: str) -> CWE:
        """Get the CWE for a given result and rule ID."""
        pass

    @classmethod
    def load_from_output_dir(cls, output_dir: Path) -> Self:
        """Load and parse a SARIF report from an output directory."""
        # Analysis Info
        analysis_info = AnalysisInfo.model_validate_json(
            (output_dir / "codesectools.json").read_text()
        )

        # Analysis outputs
        sarif_report_path = output_dir / f"{cls.sast_name.lower()}.sarif"
        if sarif_report_path.is_file():
            sarif_dict = json.load(sarif_report_path.open())
        else:
            raise MissingFile([str(sarif_report_path)])

        return cls(output_dir, sarif_dict, analysis_info)
