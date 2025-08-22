"""Provides classes for parsing Semgrep Community Edition analysis results.

This module defines `SemgrepCEFinding` and `SemgrepCEAnalysisResult` to process
the JSON output from a Semgrep scan, converting it into the standardized
format used by CodeSecTools.
"""

import json
import re
from pathlib import Path
from typing import Self

from codesectools.sasts.core.parser import AnalysisResult, Defect
from codesectools.shared.cwe import CWEs
from codesectools.utils import MissingFile


class SemgrepCEFinding(Defect):
    """Represents a single finding reported by Semgrep Community Edition.

    Parses defect data from the Semgrep JSON output to extract file, checker,
    category, CWE, severity, and line information.

    Attributes:
        severity (str): The severity level of the finding (e.g., "ERROR").
        lines (str): The line or lines of code where the finding occurred.

    """

    def __init__(self, defect_data: dict) -> None:
        """Initialize a SemgrepCEFinding instance from raw defect data.

        Args:
            defect_data: A dictionary representing a single finding, parsed
                from Semgrep Community Edition's JSON output.

        """
        if cwe_match := re.search(
            r"CWE-(\d+)", defect_data["extra"]["metadata"]["cwe"][0]
        ):
            cwe = CWEs().from_id(int(cwe_match.groups()[0]))
        else:
            cwe = CWEs().from_id(-1)

        super().__init__(
            file=Path(defect_data["path"]).name,
            checker=defect_data["check_id"].split(".")[-1],
            category=defect_data["extra"]["metadata"]["category"],
            cwe=cwe,
            data=defect_data,
        )

        # Extra
        self.severity = self.data["extra"]["severity"]
        self.lines = self.data["extra"]["lines"]


class SemgrepCEAnalysisResult(AnalysisResult):
    """Represents the complete result of a Semgrep Community Edition analysis.

    Parses the main JSON output and command output logs to populate analysis
    metadata, including timings, file lists, defects, and code coverage.

    Attributes:
        checker_category (dict): A mapping from checker names to their categories.
        coverage (float): The parsing coverage reported by Semgrep.

    """

    def __init__(self, output_dir: Path, result_data: dict, cmdout: dict) -> None:
        """Initialize a SemgrepCEAnalysisResult instance.

        Args:
            output_dir: The directory where the results are stored.
            result_data: Parsed data from the main Semgrep Community Edition JSON output.
            cmdout: Parsed data from the command output log.

        """
        super().__init__(
            name=output_dir.name,
            lang=cmdout["lang"],
            files=result_data["paths"]["scanned"],
            defects=[],
            time=result_data["time"]["profiling_times"]["total_time"],
            loc=None,
            data=(result_data, cmdout),
        )

        self.checker_category = {}
        for defect_data in result_data["results"]:
            defect = SemgrepCEFinding(defect_data)
            self.defects.append(defect)
            self.checker_category[defect.checker] = defect.category

        if match := re.search(r"Parsed lines:[^\d]*([\d\.]+)%", cmdout["logs"]):
            self.coverage = float(match.groups()[0]) / 100
            self.loc = int(self.coverage * cmdout["loc"])

    @classmethod
    def load_from_output_dir(cls, output_dir: Path) -> Self:
        """Load and parse Semgrep Community Edition analysis results from a directory.

        Reads `semgrep_output.json` and `cstools_output.json` to construct a complete
        analysis result object.

        Args:
            output_dir: The directory containing the Semgrep Community Edition output files.

        Returns:
            An instance of `SemgrepCEAnalysisResult`.

        Raises:
            MissingFile: If a required result file is not found.

        """
        # Cmdout
        cmdout = json.load((output_dir / "cstools_output.json").open())

        # Analysis outputs
        analysis_output_path = output_dir / "semgrep_output.json"
        if analysis_output_path.is_file():
            analysis_output = json.load(analysis_output_path.open("r"))
        else:
            raise MissingFile(["output.json"])

        return cls(output_dir, analysis_output, cmdout)
