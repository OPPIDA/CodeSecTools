"""Provides classes for parsing Snyk Code analysis results.

This module defines `SnykCodeIssue` and `SnykCodeAnalysisResult` to process
the SARIF JSON output from a Snyk Code scan, converting it into the standardized
format used by CodeSecTools.
"""

import json
from pathlib import Path
from typing import Self

from codesectools.sasts.core.parser import AnalysisResult, Defect
from codesectools.shared.cwe import CWE, CWEs


class SnykCodeIssue(Defect):
    """Represents a single issue reported by Snyk Code.

    Parses defect data from the Snyk Code JSON output to extract file, checker,
    category, and CWE information.
    """

    sast = "SnykCode"

    def __init__(
        self, file: str, checker: str, category: str, cwe: CWE, data: dict
    ) -> None:
        """Initialize a SnykCodeIssue instance.

        Args:
            file: The file path of the defect.
            checker: The name of the rule/checker.
            category: The category of the checker.
            cwe: The CWE associated with the defect.
            data: Raw data from the SAST tool for this defect.

        """
        super().__init__(file, checker, category, cwe, data)


class SnykCodeAnalysisResult(AnalysisResult):
    """Represents the complete result of a Snyk Code analysis.

    Parses the main JSON output and command output logs to populate analysis
    metadata, including timings, file lists, and defects.
    """

    def __init__(self, output_dir: Path, result_data: dict, cmdout: dict) -> None:
        """Initialize a SnykCodeAnalysisResult instance.

        Args:
            output_dir: The directory where the results are stored.
            result_data: Parsed data from the main Snyk Code JSON output.
            cmdout: Parsed data from the command output log.

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

        if not result_data:
            return

        for run in result_data["runs"]:
            for result in run["results"]:
                rule_index = result["ruleIndex"]
                lang, *_, checker = result["ruleId"].split("/")
                if lang != self.lang:
                    continue

                defect = SnykCodeIssue(
                    file=Path(
                        result["locations"][0]["physicalLocation"]["artifactLocation"][
                            "uri"
                        ]
                    ).name,
                    checker=checker,
                    category=run["tool"]["driver"]["rules"][rule_index][
                        "defaultConfiguration"
                    ]["level"],
                    cwe=CWEs.from_string(
                        run["tool"]["driver"]["rules"][rule_index]["properties"]["cwe"][
                            0
                        ]
                    ),
                    data=result,
                )
                self.defects.append(defect)

        self.files = list(set(d.file for d in self.defects))

    @classmethod
    def load_from_output_dir(cls, output_dir: Path) -> Self:
        """Load and parse Snyk Code analysis results from a directory.

        Reads `snyk_results.json` and `cstools_output.json` to construct a complete
        analysis result object.

        Args:
            output_dir: The directory containing the Snyk Code output files.

        Returns:
            An instance of `SnykCodeAnalysisResult`.

        """
        # Cmdout
        cmdout = json.load((output_dir / "cstools_output.json").open())

        # Analysis outputs
        analysis_output_path = output_dir / "snyk_results.json"
        if analysis_output_path.is_file():
            analysis_output = json.load(analysis_output_path.open("r"))
        else:
            analysis_output = None

        return cls(output_dir, analysis_output, cmdout)
