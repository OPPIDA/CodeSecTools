"""Provides classes for parsing Cppcheck analysis results.

This module defines `CppcheckIssue` and `CppcheckAnalysisResult` to process
the XML output from a Cppcheck scan, converting it into the standardized
format used by CodeSecTools.
"""

import json
from pathlib import Path
from typing import Self

from lxml import etree
from lxml.etree import ElementTree

from codesectools.sasts.core.parser import AnalysisResult, Defect
from codesectools.shared.cwe import CWE, CWEs
from codesectools.utils import MissingFile


class CppcheckError(Defect):
    """Represent a single error reported by Cppcheck."""

    sast = "Cppcheck"

    def __init__(
        self,
        filepath: Path,
        checker: str,
        category: str,
        cwe: CWE,
        message: str,
        lines: list[int] | None,
        data: dict,
    ) -> None:
        """Initialize a CppcheckError instance.

        Args:
            filepath: The file path of the defect.
            checker: The name of the rule/checker.
            category: The category of the checker.
            cwe: The CWE associated with the defect.
            message: The description of the defect.
            lines: A list of line numbers where the defect is located.
            data: Raw data from the SAST tool for this defect.

        """
        super().__init__(filepath, checker, category, cwe, message, lines, data)


class CppcheckAnalysisResult(AnalysisResult):
    """Represent the complete result of a Cppcheck analysis."""

    def __init__(self, output_dir: Path, xml_tree: ElementTree, cmdout: dict) -> None:
        """Initialize a CppcheckAnalysisResult instance.

        Args:
            output_dir: The directory where the results are stored.
            xml_tree: Parsed data from the main Cppcheck XML output.
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
            data=(xml_tree, cmdout),
        )

        errors = xml_tree.xpath("/results/errors/error")
        for error in errors:
            category = error.get("severity")
            if category in ["error", "warning", "style"]:
                self.defects.append(
                    CppcheckError(
                        filepath=Path(error.xpath("location")[0].get("file")),
                        checker=error.get("id"),
                        category=category,
                        cwe=CWEs.from_id(int(error.get("cwe", -1))),
                        message=error.get("msg"),
                        lines=[
                            int(location.get("line"))
                            for location in error.xpath("location")
                        ],
                        data=error.attrib,
                    )
                )

        self.files = list(set(d.filepath_str for d in self.defects))

    @classmethod
    def load_from_output_dir(cls, output_dir: Path) -> Self:
        """Load and parse Cppcheck analysis results from a directory.

        Read `cppcheck_output.xml` and `cstools_output.json` to construct a complete
        analysis result object.

        Args:
            output_dir: The directory containing the Cppcheck output files.

        Returns:
            An instance of `CppcheckAnalysisResult`.

        Raises:
            MissingFile: If a required result file is not found.

        """
        # Cmdout
        cmdout = json.load((output_dir / "cstools_output.json").open())

        # Analysis outputs
        analysis_output_path = output_dir / "cppcheck_output.xml"
        if analysis_output_path.is_file():
            analysis_output = etree.parse(analysis_output_path)
        else:
            raise MissingFile(["cppcheck_output.xml"])

        return cls(output_dir, analysis_output, cmdout)
