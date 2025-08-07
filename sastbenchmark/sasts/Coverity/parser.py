import glob
import os
import re
from typing import Self

import xmltodict
import yaml

from sastbenchmark.sasts._base.parser import AnalysisResult, Defect
from sastbenchmark.sasts.Coverity.constants import LANG, TYPE_TO_CWE
from sastbenchmark.utils import MissingFile


class CoverityDefect(Defect):
    def __init__(self, defect_data: dict) -> None:
        super().__init__(
            file=os.path.basename(defect_data["file"]),
            checker=defect_data["checker"],
            category=None,
            cwe_id=TYPE_TO_CWE.get(defect_data["type"], None),
            data=defect_data,
        )

        self.lang = self.data["lang"].lower()

        if self.checker.startswith("SIGMA"):
            self.category = "SIGMA"
        elif self.checker.startswith("FB"):
            self.category = "SPOTBUGS"
        else:
            if self.lang in LANG.keys():
                for set_name, checker_set in LANG[self.lang]["checker_sets"].items():
                    if self.checker in checker_set:
                        self.category = set_name
                        break

        # Extra
        self.function = self.data["function"]


class CoverityAnalysisResult(AnalysisResult):
    def __init__(
        self,
        result_dir: str,
        result_data: dict,
        config_data: str,
        captured_list: str,
        defects: list[Defect],
    ) -> None:
        super().__init__(
            name=os.path.basename(result_dir),
            lang=None,
            files=None,
            defects=defects,
            time=None,
            loc=None,
            data=(result_data, config_data, captured_list),
        )

        self.metrics = {}
        for metric in result_data["coverity"]["metrics"]["metric"]:
            self.metrics[metric["name"]] = metric["value"]

        self.time = int(self.metrics["time"])

        self.files = list(
            map(lambda line: os.path.basename(line), captured_list.splitlines())
        )

        file_count = 0
        for lang, pattern in LANG.items():
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
    def load_from_result_dir(cls, result_dir: str) -> Self:
        # Analysis metrics
        file_path = os.path.join(result_dir, "ANALYSIS.metrics.xml")
        if os.path.isfile(file_path):
            analysis_data = xmltodict.parse(open(file_path, "rb"))
        else:
            raise MissingFile(["ANALYSIS.metrics.xml"])

        # Config
        file_path = os.path.join(result_dir, "coverity.yaml")
        if os.path.isfile(file_path):
            config_data = yaml.load(open(file_path, "r"), Loader=yaml.Loader)
        else:
            config_data = None

        # Captured source file list
        captured_list = ""
        for file in glob.glob(os.path.join(result_dir, "capture-files-src-list*")):
            captured_list += open(file, "r").read()

        # Defects
        defects = []
        for file in glob.glob(os.path.join(result_dir, "*errors.xml")):
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

        return cls(result_dir, analysis_data, config_data, captured_list, defects)
