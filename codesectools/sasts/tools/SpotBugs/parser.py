"""Provides classes for parsing SpotBugs analysis results.

This module defines `SpotBugsIssue` and `SpotBugsAnalysisResult` to process
the SARIF JSON output from a SpotBugs scan, converting it into the standardized
format used by CodeSecTools.
"""

import json
from pathlib import Path
from typing import Self

from codesectools.sasts.core.parser import AnalysisResult, Defect
from codesectools.shared.cwe import CWE, CWEs
from codesectools.utils import MissingFile


class SpotBugsIssue(Defect):
    """Represent a single issue reported by SpotBugs."""

    sast = "SpotBugs"

    def __init__(
        self,
        filepath: Path,
        checker: str,
        category: str,
        cwe: CWE,
        message: str,
        location: tuple[int, int] | None,
        data: dict,
    ) -> None:
        """Initialize a SpotBugsIssue instance.

        Args:
            filepath: The file path of the defect.
            checker: The name of the rule/checker.
            category: The category of the checker.
            cwe: The CWE associated with the defect.
            message: The description of the defect.
            location: A tuple with start and end line numbers of the defect, or None.
            data: Raw data from the SAST tool for this defect.

        """
        super().__init__(filepath, checker, category, cwe, message, location, data)


class SpotBugsAnalysisResult(AnalysisResult):
    """Represent the complete result of a SpotBugs analysis."""

    def __init__(self, output_dir: Path, result_data: dict, cmdout: dict) -> None:
        """Initialize a SpotBugsAnalysisResult instance.

        Args:
            output_dir: The directory where the results are stored.
            result_data: Parsed data from the main SpotBugs JSON output.
            cmdout: A dictionary with metadata from the command execution.

        """
        super().__init__(
            name=output_dir.name,
            source_path=Path(cmdout["project_dir"]),
            lang=cmdout["lang"],
            files=[],
            defects=[],
            time=cmdout["duration"],
            loc=cmdout["loc"],
            data=(result_data, cmdout),
        )

        if not result_data:
            return

        partial_parents = {}

        for run in result_data["runs"]:
            for result in run["results"]:
                rule_index = result["ruleIndex"]
                checker = result["ruleId"]

                partial_filepath = Path(
                    result["locations"][0]["physicalLocation"]["artifactLocation"][
                        "uri"
                    ]
                )
                if partial_filepath.parent not in partial_parents:
                    filepath = next(
                        self.source_path.rglob(str(partial_filepath))
                    ).relative_to(self.source_path)
                    partial_parents[partial_filepath.parent] = filepath.parent
                else:
                    filepath = (
                        partial_parents[partial_filepath.parent] / partial_filepath.name
                    )

                defect = SpotBugsIssue(
                    filepath=filepath,
                    checker=checker,
                    category=run["tool"]["driver"]["rules"][rule_index]["properties"][
                        "tags"
                    ][0],
                    cwe=CWEs.from_id(
                        int(
                            run["tool"]["driver"]["rules"][rule_index].get(
                                "relationships", [{"target": {"id": -1}}]
                            )[0]["target"]["id"]
                        )
                    ),
                    message=result["message"]["text"],
                    location=(
                        result["locations"][0]["physicalLocation"]
                        .get("region", {})
                        .get("startLine", None),
                        result["locations"][0]["physicalLocation"]
                        .get("region", {})
                        .get("endLine", None),
                    ),
                    data=result,
                )
                if defect.category in ["SECURITY", "CORRECTNESS", "MT_CORRECTNESS"]:
                    self.defects.append(defect)

        self.files = list(set(d.filepath_str for d in self.defects))

    @classmethod
    def load_from_output_dir(cls, output_dir: Path) -> Self:
        """Load and parse SpotBugs analysis results from a directory.

        Read `spotbugs_output.json` and `cstools_output.json` to construct a complete
        analysis result object.

        Args:
            output_dir: The directory containing the SpotBugs output files.

        Returns:
            An instance of `SpotBugsAnalysisResult`.

        Raises:
            MissingFile: If a required result file is not found.

        """
        # Cmdout
        cmdout = json.load((output_dir / "cstools_output.json").open())

        # Analysis outputs
        analysis_output_path = output_dir / "spotbugs_output.json"
        if analysis_output_path.is_file():
            analysis_output = json.load(analysis_output_path.open("r"))
        else:
            raise MissingFile(["spotbugs_output.json"])

        return cls(output_dir, analysis_output, cmdout)
