"""Provides classes for parsing Coverity analysis results.

This module defines `CoverityDefect` and `CoverityAnalysisResult` to process
the XML and YAML output from a Coverity scan, converting it into the standardized
format used by CodeSecTools.
"""

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Self

from codesectools.sasts.core.parser import AnalysisResult, Defect
from codesectools.shared.cwe import CWEs
from codesectools.utils import USER_CONFIG_DIR, MissingFile

USER_COVERITY_DIR = USER_CONFIG_DIR / "Coverity"


class CoverityConfig:
    """Handle the loading and parsing of Coverity configuration files."""

    def __init__(self) -> None:
        """Initialize the CoverityConfig instance."""
        self._type_to_cwe = None
        self._languages = None
        self._color_mapping = None

    @staticmethod
    @lru_cache(maxsize=None)
    def _load_issue_types_file() -> dict | None:
        """Load and parse the issueTypes.json file."""
        types_file = USER_COVERITY_DIR / "issueTypes.json"
        if types_file.is_file():
            return json.load(types_file.open())
        return None

    @staticmethod
    @lru_cache(maxsize=None)
    def _load_config_file() -> dict | None:
        """Load and parse the config.json file."""
        config_file = USER_COVERITY_DIR / "config.json"
        if config_file.is_file():
            return json.load(config_file.open())
        return None

    @property
    def type_to_cwe(self) -> dict:
        """Get a mapping from Coverity issue types to CWE IDs."""
        if self._type_to_cwe is None:
            types_data = self._load_issue_types_file()
            if types_data and "issue_type" in types_data:
                self._type_to_cwe = {
                    type_info["type"]: type_info["cim_checker_properties"][
                        "cweCategory"
                    ]
                    for type_info in types_data["issue_type"]
                }
            else:
                self._type_to_cwe = {}
        return self._type_to_cwe

    @property
    def languages(self) -> dict:
        """Get the language configuration for Coverity."""
        if self._languages is None:
            config_data = self._load_config_file()
            if config_data and "languages" in config_data:
                self._languages = config_data["languages"]
            else:
                self._languages = {}
        return self._languages

    @property
    def color_mapping(self) -> dict:
        """Get the color mapping for Coverity issue categories."""
        if self._color_mapping is None:
            config_data = self._load_config_file()
            if config_data and "color_mapping" in config_data:
                self._color_mapping = config_data["color_mapping"]
            else:
                self._color_mapping = {}
        return self._color_mapping


class CoverityDefect(Defect):
    """Represents a single defect found by Coverity.

    Parses defect data to extract file, checker, category, and CWE information.
    It also determines the checker category based on predefined sets.

    Attributes:
        lang (str): The programming language of the file with the defect.
        function (str): The function in which the defect was found.

    """

    sast = "Coverity"

    def __init__(self, defect_data: dict) -> None:
        """Initialize a CoverityDefect instance from raw defect data.

        Args:
            defect_data: A dictionary representing a single defect, parsed
                from Coverity's XML output.

        """
        super().__init__(
            filepath=Path(defect_data["file"]),
            checker=defect_data["checker"],
            category="",
            cwe=CWEs.from_id(CoverityConfig().type_to_cwe.get(defect_data["type"], -1)),
            message="",  # TODO
            lines=[defect_data["line"]],
            data=defect_data,
        )

        self.lang = defect_data["lang"].lower()

        if self.checker.startswith("SIGMA"):
            self.category = "SIGMA"
        elif self.checker.startswith("FB"):
            self.category = "SPOTBUGS"
        else:
            if self.lang in CoverityConfig().languages.keys():
                for set_name, checker_set in (
                    CoverityConfig().languages[self.lang]["checker_sets"].items()
                ):
                    if self.checker in checker_set:
                        self.category = set_name
                        break

        # Extra
        self.function = defect_data["function"]


class CoverityAnalysisResult(AnalysisResult):
    """Represents the complete result of a Coverity analysis.

    Parses various output files from a Coverity run to populate analysis
    metadata, including metrics, configuration, file lists, and defects.

    Attributes:
        metrics (dict): A dictionary of metrics from the analysis.
        config (dict): The Coverity configuration used for the scan.
        analysis_cmd (str): The command used to run the analysis.
        code_lines_by_lang (dict): A dictionary mapping languages to their
            line counts.

    """

    def __init__(
        self,
        output_dir: Path,
        result_data: dict,
        config_data: str,
        captured_list: str,
        defects: list[Defect],
        cmdout: dict,
    ) -> None:
        """Initialize a CoverityAnalysisResult instance.

        Args:
            output_dir: The directory where the results are stored.
            result_data: Parsed data from ANALYSIS.metrics.xml.
            config_data: Parsed data from coverity.yaml.
            captured_list: A string containing the list of captured source files.
            defects: A list of `CoverityDefect` objects.
            cmdout: A dictionary with metadata from the command execution.

        """
        super().__init__(
            name=output_dir.name,
            source_path=Path(cmdout["project_dir"]),
            lang=cmdout["lang"],
            files=[],
            defects=defects,
            time=0,
            loc=0,
            data=(result_data, config_data, captured_list, cmdout),
        )

        self.metrics = {}
        for metric in result_data["coverity"]["metrics"]["metric"]:
            self.metrics[metric["name"]] = metric["value"]

        self.time = int(self.metrics["time"])

        self.files = list(map(lambda line: str(Path(line)), captured_list.splitlines()))

        file_count = 0
        for lang, pattern in CoverityConfig().languages.items():
            include = pattern["include"]
            exclude = pattern["exclude"]
            files = [
                file
                for file in self.files
                if re.search(include, file) and not re.search(exclude, file)
            ]
            if len(files) > file_count:
                file_count = len(files)
                self.lang = lang

        # Extra
        self.config = config_data
        self.analysis_cmd = self.metrics["args"]
        self.code_lines_by_lang = {}
        for key in self.metrics.keys():
            if r := re.search(r"(.*)-code-lines", key):
                self.code_lines_by_lang[r.group(1)] = int(self.metrics[key])
        self.loc = self.code_lines_by_lang[self.lang]

    @classmethod
    def load_from_output_dir(cls, output_dir: Path) -> Self:
        """Load and parse Coverity analysis results from a directory.

        Reads ANALYSIS.metrics.xml, coverity.yaml, captured file lists, and
        error XML files to construct a complete analysis result object.

        Args:
            output_dir: The directory containing the Coverity output files.

        Returns:
            An instance of `CoverityAnalysisResult`.

        Raises:
            MissingFile: If a required result file is not found.

        """
        import xmltodict
        import yaml

        cmdout = json.load((output_dir / "cstools_output.json").open())

        # Analysis metrics
        filepath = output_dir / "ANALYSIS.metrics.xml"
        if filepath.is_file():
            analysis_data = xmltodict.parse(filepath.open("rb"))
        else:
            raise MissingFile(["ANALYSIS.metrics.xml"])

        # Config
        filepath = output_dir / "coverity.yaml"
        if filepath.is_file():
            config_data = yaml.load(filepath.open("r"), Loader=yaml.Loader)
        else:
            config_data = ""

        # Captured source file list
        captured_list = ""
        for file in output_dir.glob("capture-files-src-list*"):
            captured_list += open(file, "r").read()

        # Defects
        defects = []
        for file in output_dir.glob("*errors.xml"):
            f = open(file, "r")
            try:
                errors = xmltodict.parse(f"<root>{f.read()}</root>".encode())["root"][
                    "error"
                ]
            except TypeError:
                pass

            if isinstance(errors, list):
                for error in errors:
                    defects.append(CoverityDefect(error))
            else:
                defects.append(CoverityDefect(errors))

        return cls(
            output_dir, analysis_data, config_data, captured_list, defects, cmdout
        )
