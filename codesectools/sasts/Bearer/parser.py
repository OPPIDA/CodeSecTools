"""Provide classes for parsing Bearer analysis results.

This module defines `BearerFinding` and `BearerAnalysisResult` to process
the JSON output from a Bearer scan, converting it into the standardized
format used by CodeSecTools.
"""

import json
from pathlib import Path
from typing import Self

from codesectools.sasts.core.parser import AnalysisResult, Defect
from codesectools.shared.cwe import CWEs
from codesectools.utils import MissingFile


class BearerFinding(Defect):
    """Represent a single defect found by Bearer."""

    def __init__(self, defect_data: dict, severity: str) -> None:
        """Initialize a BearerFinding instance.

        Args:
            defect_data: A dictionary representing a single finding from the JSON output.
            severity: The severity level of the finding.

        """
        super().__init__(
            file=Path(defect_data["filename"]).name,
            checker=defect_data["id"],
            category=severity,
            cwe=CWEs.from_id(int(defect_data["cwe_ids"][0])),
            data=defect_data,
        )


class BearerAnalysisResult(AnalysisResult):
    """Represent the complete result of a Bearer analysis."""

    def __init__(self, output_dir: Path, result_data: dict, cmdout: dict) -> None:
        """Initialize a BearerAnalysisResult instance.

        Args:
            output_dir: The directory where the results are stored.
            result_data: Parsed data from the main Bearer JSON output.
            cmdout: A dictionary with metadata from the command execution.

        """
        super().__init__(
            name=output_dir.name,
            lang=cmdout["lang"],
            files=[],
            defects=[],
            time=cmdout["duration"],
            loc=cmdout["loc"],
            data=(result_data, cmdout),
        )

        for severity, findings in result_data.items():
            for finding in findings:
                self.files.append(Path(finding["filename"]).name)
                self.defects.append(
                    BearerFinding(defect_data=finding, severity=severity)
                )

    @classmethod
    def load_from_output_dir(cls, output_dir: Path) -> Self:
        """Load and parse Bearer analysis results from a directory.

        Read `bearer_output.json` and `cstools_output.json` to construct a complete
        analysis result object.

        Args:
            output_dir: The directory containing the Bearer output files.

        Returns:
            An instance of `BearerAnalysisResult`.

        Raises:
            MissingFile: If a required result file is not found.

        """
        # Cmdout
        cmdout = json.load((output_dir / "cstools_output.json").open())

        # Analysis outputs
        analysis_output_path = output_dir / "bearer_output.json"
        if analysis_output_path.is_file():
            analysis_output = json.load(analysis_output_path.open("r"))
        else:
            raise MissingFile(["bearer_output.json"])

        return cls(output_dir, analysis_output, cmdout)
