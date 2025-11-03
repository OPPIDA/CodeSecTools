"""Defines the core abstract classes for parsing SAST tool results.

This module provides the `Defect` and `AnalysisResult` classes, which serve as
standardized data structures for holding information about vulnerabilities and
the overall analysis process. Each SAST integration must implement a concrete
subclass of `AnalysisResult` to parse its specific output format.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Self

from codesectools.shared.cwe import CWE


class Defect:
    """Represent a single defect or finding reported by a SAST tool.

    Attributes:
        sast (str): The name of the SAST tool that reported the defect.
        filepath (Path): The path to the file where the defect was found.
        filepath_str (str): The string representation of the file path.
        filename (str): The name of the file.
        checker (str): The name of the checker or rule that reported the defect.
        category (str): The category of the checker (e.g., security, performance).
        cwe (CWE): The CWE associated with the defect.
        message (str): The description of the defect.
        location (tuple[int, int] | None): A tuple with the start and end line numbers of the defect.
        data (tuple[Any]): Raw data from the SAST tool for this defect.

    """

    sast: str

    def __init__(
        self,
        filepath: Path,
        checker: str,
        category: str,
        cwe: CWE,
        message: str,
        lines: list[int] | None,
        data: tuple[Any],
    ) -> None:
        """Initialize a Defect instance.

        Args:
            filepath: The file path of the defect.
            checker: The name of the rule/checker.
            category: The category of the checker.
            cwe: The CWE associated with the defect.
            message: The description of the defect.
            lines: A list of line numbers where the defect is located.
            data: Raw data from the SAST tool for this defect.

        """
        self.filepath = filepath
        self.filepath_str = str(filepath)
        self.filename = filepath.name
        self.checker = checker
        self.category = category
        self.cwe = cwe
        self.message = message
        self.lines = lines
        self.data = data

    def __repr__(self) -> str:
        """Return a developer-friendly string representation of the Defect.

        Returns:
            A string showing the class name and key attributes of the defect.

        """
        return f"""{self.__class__.__name__}(
    file: \t{self.file}
    checker: \t{self.checker}
    category: \t{self.category}
    cwe: \t{self.cwe}
)"""


class AnalysisResult(ABC):
    """Abstract base class for holding the parsed results of a SAST analysis.

    Attributes:
        name (str): The name of the analyzed project or dataset.
        source_path (Path): The path to the analyzed source code.
        lang (str): The primary programming language analyzed.
        files (list[str]): A list of files that were analyzed.
        defects (list[Defect]): A list of `Defect` objects found.
        time (float): The duration of the analysis in seconds.
        loc (int): The number of lines of code analyzed.
        data (tuple[Any]): Raw data from the SAST tool's output.

    """

    def __init__(
        self,
        name: str,
        source_path: Path,
        lang: str,
        files: list[str],
        defects: list[Defect],
        time: float,
        loc: int,
        data: tuple[Any],
    ) -> None:
        """Initialize an AnalysisResult instance.

        Args:
            name: The name of the analyzed project/dataset.
            source_path: The path to the analyzed source code.
            lang: The programming language of the code.
            files: A list of analyzed files.
            defects: A list of `Defect` objects.
            time: The analysis duration in seconds.
            loc: The lines of code analyzed.
            data: Raw data from the SAST tool's output.

        """
        self.name = name
        self.source_path = source_path
        self.lang = lang
        self.files = files
        self.defects = defects
        self.time = time
        self.loc = loc
        self.data = data

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
    def load_from_output_dirs(cls, output_dirs: list[str]) -> list[Self]:
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

    def checker_to_category(self, checker: str) -> str:
        """Get the category for a given checker name.

        Args:
            checker: The name of the checker.

        Returns:
            The category string, or "NONE" if not found.

        """
        for defect in self.defects:
            if checker == defect.checker:
                return defect.category
        return "NONE"

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

    def stats_by_categories(self) -> dict:
        """Calculate statistics on defects, grouped by category.

        Returns:
            A dictionary where keys are category names and values are dicts
            containing counts and checker lists.

        """
        stats = {}
        for defect in self.defects:
            if defect.category not in stats.keys():
                stats[defect.category] = {
                    "count": 1,
                    "checkers": [defect.checker],
                    "unique": 1,
                }
            else:
                stats[defect.category]["checkers"].append(defect.checker)
                stats[defect.category]["count"] = len(
                    stats[defect.category]["checkers"]
                )
                stats[defect.category]["unique"] = len(
                    set(stats[defect.category]["checkers"])
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
