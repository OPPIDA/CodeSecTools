"""Provides classes for parsing Semgrep analysis results.

This module defines `SemgrepFinding` and `SemgrepAnalysisResult` to process
the JSON output from a Semgrep scan, converting it into the standardized
format used by CodeSecTools.
"""

import json
import re
from pathlib import Path
from typing import Self

from codesectools.sasts.core.parser import AnalysisResult, Defect
from codesectools.utils import MissingFile


class SemgrepFinding(Defect):
    """Represents a single finding reported by Semgrep.

    Parses defect data from the Semgrep JSON output to extract file, checker,
    category, CWE, severity, and line information.

    Attributes:
        severity (str): The severity level of the finding (e.g., "ERROR").
        lines (str): The line or lines of code where the finding occurred.

    """

    def __init__(self, defect_data: dict) -> None:
        """Initialize a SemgrepFinding instance from raw defect data.

        Args:
            defect_data: A dictionary representing a single finding, parsed
                from Semgrep's JSON output.

        """
        if cwe_id_match := re.search(
            r"CWE-(\d+)", defect_data["extra"]["metadata"]["cwe"][0]
        ):
            cwe_id = int(cwe_id_match.groups()[0])
        else:
            cwe_id = None

        super().__init__(
            file=Path(defect_data["path"]).name,
            checker=defect_data["check_id"].split(".")[-1],
            category=defect_data["extra"]["metadata"]["category"],
            cwe_id=cwe_id,
            data=defect_data,
        )

        # Extra
        self.severity = self.data["extra"]["severity"]
        self.lines = self.data["extra"]["lines"]


class SemgrepAnalysisResult(AnalysisResult):
    """Represents the complete result of a Semgrep analysis.

    Parses the main JSON output and command output logs to populate analysis
    metadata, including timings, file lists, defects, and code coverage.

    Attributes:
        checker_category (dict): A mapping from checker names to their categories.
        coverage (float): The parsing coverage reported by Semgrep.

    """

    def __init__(self, result_dir: Path, result_data: dict, cmdout: dict) -> None:
        """Initialize a SemgrepAnalysisResult instance.

        Args:
            result_dir: The directory where the results are stored.
            result_data: Parsed data from the main Semgrep JSON output.
            cmdout: Parsed data from the command output log.

        """
        super().__init__(
            name=result_dir.name,
            lang=result_data["interfile_languages_used"],
            files=result_data["paths"]["scanned"],
            defects=[],
            time=result_data["time"]["profiling_times"]["total_time"],
            loc=None,
            data=(result_data, cmdout),
        )

        self.checker_category = {}
        for defect_data in result_data["results"]:
            defect = SemgrepFinding(defect_data)
            self.defects.append(defect)
            self.checker_category[defect.checker] = defect.category

        if match := re.search(r"Parsed lines:[^\d]*([\d\.]+)%", cmdout["logs"]):
            self.coverage = float(match.groups()[0]) / 100
            self.loc = int(self.coverage * cmdout["loc"])

    @classmethod
    def load_from_result_dir(cls, result_dir: Path) -> Self:
        """Load and parse Semgrep analysis results from a directory.

        Reads `output.json` and `cstools_cmdout.json` to construct a complete
        analysis result object.

        Args:
            result_dir: The directory containing the Semgrep output files.

        Returns:
            An instance of `SemgrepAnalysisResult`.

        Raises:
            MissingFile: If a required result file is not found.

        """
        # Cmdout
        cmdout = json.load((result_dir / "cstools_output.json").open())

        # Analysis outputs
        analysis_output_path = result_dir / "output.json"
        if analysis_output_path.is_file():
            analysis_output = json.load(analysis_output_path.open("r"))
        else:
            raise MissingFile(["output.json"])

        return cls(result_dir, analysis_output, cmdout)
