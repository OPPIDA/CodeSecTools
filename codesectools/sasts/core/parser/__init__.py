"""Defines the core abstract classes for parsing SAST tool results.

This module provides the `Defect` and `AnalysisResult` classes, which serve as
standardized data structures for holding information about vulnerabilities and
the overall analysis process. Each SAST integration must implement a concrete
subclass of `AnalysisResult` to parse its specific output format.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Literal, Self
from urllib.parse import unquote

from codesectools.shared.cwe import CWE


class Defect:
    """Represent a single defect or finding reported by a SAST tool.

    Attributes:
        filepath (Path): The path to the file where the defect was found.
        filepath_str (str): The string representation of the file path.
        filename (str): The name of the file.
        sast_name (str): The name of the SAST tool that reported the defect.
        checker (str): The name of the checker or rule that reported the defect.
        level (Literal["none", "note", "warning", "error"]): The severity level of the defect.
        level (str): The level of the checker (e.g., security, performance).
        cwe (CWE): The CWE associated with the defect.
        message (str): The description of the defect.
        lines (list[int] | None): A list of line numbers where the defect is located.

    """

    def __init__(
        self,
        sast_name: str,
        filepath: Path,
        checker: str,
        level: Literal["none", "note", "warning", "error"],
        cwe: CWE,
        message: str,
        lines: list[int] | None,
    ) -> None:
        """Initialize a Defect instance.

        Args:
            sast_name: The name of the SAST tool.
            filepath: The file path of the defect.
            checker: The name of the rule/checker.
            level: The severity level of the defect.
            cwe: The CWE associated with the defect.
            message: The description of the defect.
            lines: A list of line numbers where the defect is located.

        """
        # URL decode
        filepath = Path(unquote(str(filepath)))
        if not filepath.is_file():
            raise FileNotFoundError(filepath.resolve())
        self.filepath = filepath
        self.filepath_str = str(filepath.resolve())
        self.filename = filepath.name
        self.sast_name = sast_name
        self.checker = checker
        self.level = level
        self.cwe = cwe
        self.message = message
        self.lines = lines

    def __repr__(self) -> str:
        """Return a developer-friendly string representation of the Defect.

        Returns:
            A string showing the class name and key attributes of the defect.

        """
        return f"""{self.__class__.__name__}(
    sast: \t{self.sast_name}       
    filepath: \t{self.filepath}
    checker: \t{self.checker}
    level: \t{self.level}
    cwe: \t{self.cwe}
)"""


class AnalysisResult(ABC):
    """Abstract base class for a SAST tool's analysis result.

    This class provides a standardized structure for holding analysis data,
    including defects, execution time, and language information. It also offers
    methods for calculating statistics based on the results.

    Attributes:
        sast_name (str): The name of the SAST tool that produced the result.
        name (str): The name of the project or dataset analyzed.
        source_path (Path): The path to the source code that was analyzed.
        lang (str): The programming language of the source code.
        files (list[str]): A list of file paths that were part of the analysis.
        defects (list[Defect]): A list of `Defect` objects found during analysis.
        time (float): The total time taken for the analysis in seconds.
        lines_of_codes (int): The number of lines of code analyzed.

    """

    sast_name: str
    level_color_map = {
        "error": "red",
        "warning": "orange",
        "note": "yellow",
        "none": "gray",
    }

    def __init__(
        self,
        name: str,
        source_path: Path,
        lang: str,
        defects: list[Defect],
        time: float,
        lines_of_codes: int,
    ) -> None:
        """Initialize an AnalysisResult instance.

        Args:
            name: The name of the project or dataset.
            source_path: The path to the analyzed source code.
            lang: The programming language of the source code.
            defects: A list of found defects.
            time: The analysis duration in seconds.
            lines_of_codes: The number of lines of code analyzed.

        """
        self.name = name
        self.source_path = source_path
        self.lang = lang
        self.defects = defects
        self.time = time
        self.lines_of_codes = lines_of_codes

    @property
    def files(self) -> list[str]:
        """Get the list of unique file paths containing defects."""
        return list(set(d.filepath_str for d in self.defects))

    def __repr__(self) -> str:
        """Return a developer-friendly string representation of the AnalysisResult.

        Returns:
            A string showing key metrics of the analysis.

        """
        return f"""{self.__class__.__name__}(
    name: \t{self.name}
    lang: \t{self.lang}
    files: \t{self.files}
    file_count: \t{len(self.files)}
    defect_count: \t{len(self.defects)}
    time: \t{self.time}
)"""

    @classmethod
    @abstractmethod
    def load_from_output_dir(cls, output_dir: Path) -> Self:
        """Load and parse analysis results from a specified directory.

        This method must be implemented by subclasses to handle the specific
        output files of a SAST tool.

        Args:
            output_dir: The directory containing the raw analysis output files.

        Returns:
            An instance of the `AnalysisResult` subclass.

        """
        pass

    @classmethod
    def load_from_output_dirs(cls, output_dirs: list[Path]) -> list[Self]:
        """Load and parse analysis results from multiple directories.

        Args:
            output_dirs: An iterable of directory paths containing results.

        Returns:
            A list of `AnalysisResult` subclass instances.

        """
        analysis_results = []
        for output_dir in output_dirs:
            analysis_results.append(cls.load_from_output_dir(output_dir))
        return analysis_results

    def checker_to_level(self, checker: str) -> str:
        """Map a checker name to its severity level.

        Args:
            checker: The name of the checker.

        Returns:
            The level string for the checker, or "none" if not found.

        """
        for defect in self.defects:
            if checker == defect.checker:
                return defect.level
        return "none"

    def stats_by_checkers(self) -> dict:
        """Calculate statistics on defects, grouped by checker.

        Returns:
            A dictionary where keys are checker names and values are dicts
            containing defect counts and affected files.

        """
        stats = {}
        for defect in self.defects:
            if defect.checker not in stats.keys():
                stats[defect.checker] = {"count": 1, "files": [defect.filepath_str]}
            else:
                stats[defect.checker]["files"].append(defect.filepath_str)
                stats[defect.checker]["count"] += 1

        return stats

    def stats_by_levels(self) -> dict:
        """Calculate statistics on defects, grouped by level.

        Returns:
            A dictionary where keys are level names and values are dicts
            containing counts and checker lists.

        """
        stats = {}
        for defect in self.defects:
            if defect.level not in stats.keys():
                stats[defect.level] = {
                    "count": 1,
                    "checkers": [defect.checker],
                    "unique": 1,
                }
            else:
                stats[defect.level]["checkers"].append(defect.checker)
                stats[defect.level]["count"] = len(stats[defect.level]["checkers"])
                stats[defect.level]["unique"] = len(
                    set(stats[defect.level]["checkers"])
                )

        return stats

    def stats_by_files(self) -> dict:
        """Calculate statistics on defects, grouped by file.

        Returns:
            A dictionary where keys are filenames and values are dicts
            containing defect counts and the checkers that fired.

        """
        stats = {}
        for defect in self.defects:
            if defect.filepath_str not in stats.keys():
                stats[defect.filepath_str] = {"count": 1, "checkers": [defect.checker]}
            else:
                stats[defect.filepath_str]["checkers"].append(defect.checker)
                stats[defect.filepath_str]["count"] += 1

        return stats

    def stats_by_cwes(self) -> dict:
        """Calculate statistics on defects, grouped by CWE ID.

        Returns:
            A dictionary where keys are CWE IDs and values are dicts
            containing defect counts and affected files.

        """
        stats = {}
        for defect in self.defects:
            if defect.cwe not in stats.keys():
                stats[defect.cwe] = {"count": 1, "files": [defect.filepath_str]}
            else:
                stats[defect.cwe]["files"].append(defect.filepath_str)
                stats[defect.cwe]["count"] += 1

        return stats
