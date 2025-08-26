"""Provides classes for parsing Coverity analysis results.

This module defines `CoverityDefect` and `CoverityAnalysisResult` to process
the XML and YAML output from a Coverity scan, converting it into the standardized
format used by CodeSecTools.
"""

import json
import re
from pathlib import Path
from typing import Self

import xmltodict
import yaml

from codesectools.sasts.core.parser import AnalysisResult, Defect
from codesectools.shared.cwe import CWEs
from codesectools.utils import USER_CONFIG_DIR, MissingFile

"""Loads and provides configuration for the Coverity integration.

This module reads `issueTypes.json` and `config.json` from the user's
Coverity configuration directory. It creates mappings and settings
used by the Coverity SAST integration.

Attributes:
    USER_COVERITY_DIR (Path): The path to the user's Coverity config directory.
    TYPE_TO_CWE (dict): A mapping from Coverity issue types to CWE IDs.
    LANGUAGES (dict): Configuration for supported languages.
    COLOR_MAPPING (dict): A mapping of result categories to colors for plotting.

"""

USER_COVERITY_DIR = USER_CONFIG_DIR / "Coverity"

types_file = USER_COVERITY_DIR / "issueTypes.json"

if types_file.is_file():
    TYPES = json.load(types_file.open())["issue_type"]

    TYPE_TO_CWE = {}
    for type in TYPES:
        TYPE_TO_CWE[type["type"]] = type["cim_checker_properties"]["cweCategory"]
else:
    raise MissingFile([types_file.name])

config_file = USER_COVERITY_DIR / "config.json"

if config_file.is_file():
    config = json.load(config_file.open())
    LANGUAGES = config["languages"]
    COLOR_MAPPING = config["color_mapping"]
else:
    raise MissingFile([config_file.name])


class CoverityDefect(Defect):
    """Represents a single defect found by Coverity.

    Parses defect data to extract file, checker, category, and CWE information.
    It also determines the checker category based on predefined sets.

    Attributes:
        lang (str): The programming language of the file with the defect.
        function (str): The function in which the defect was found.

    """

    def __init__(self, defect_data: dict) -> None:
        """Initialize a CoverityDefect instance from raw defect data.

        Args:
            defect_data: A dictionary representing a single defect, parsed
                from Coverity's XML output.

        """
        super().__init__(
            file=Path(defect_data["file"]).name,
            checker=defect_data["checker"],
            category=None,
            cwe=CWEs.from_id(TYPE_TO_CWE.get(defect_data["type"], -1)),
            data=defect_data,
        )

        self.lang = self.data["lang"].lower()

        if self.checker.startswith("SIGMA"):
            self.category = "SIGMA"
        elif self.checker.startswith("FB"):
            self.category = "SPOTBUGS"
        else:
            if self.lang in LANGUAGES.keys():
                for set_name, checker_set in LANGUAGES[self.lang][
                    "checker_sets"
                ].items():
                    if self.checker in checker_set:
                        self.category = set_name
                        break

        # Extra
        self.function = self.data["function"]


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
            lang=cmdout["lang"],
            files=None,
            defects=defects,
            time=None,
            loc=None,
            data=(result_data, config_data, captured_list, cmdout),
        )

        self.metrics = {}
        for metric in result_data["coverity"]["metrics"]["metric"]:
            self.metrics[metric["name"]] = metric["value"]

        self.time = int(self.metrics["time"])

        self.files = list(map(lambda line: Path(line).name, captured_list.splitlines()))

        file_count = 0
        for lang, pattern in LANGUAGES.items():
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
        cmdout = json.load((output_dir / "cstools_output.json").open())

        # Analysis metrics
        file_path = output_dir / "ANALYSIS.metrics.xml"
        if file_path.is_file():
            analysis_data = xmltodict.parse(file_path.open("rb"))
        else:
            raise MissingFile(["ANALYSIS.metrics.xml"])

        # Config
        file_path = output_dir / "coverity.yaml"
        if file_path.is_file():
            config_data = yaml.load(file_path.open("r"), Loader=yaml.Loader)
        else:
            config_data = None

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
