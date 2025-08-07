import json
import os
import re
from typing import Self

from sastbenchmark.sasts._base.parser import AnalysisResult, Defect
from sastbenchmark.utils import MissingFile


class SemgrepFinding(Defect):
    def __init__(self, defect_data: dict) -> None:
        if cwe_id_match := re.search(
            r"CWE-(\d+)", defect_data["extra"]["metadata"]["cwe"][0]
        ):
            cwe_id = int(cwe_id_match.groups()[0])
        else:
            cwe_id = None

        super().__init__(
            file=os.path.basename(defect_data["path"]),
            checker=defect_data["check_id"].split(".")[-1],
            category=defect_data["extra"]["metadata"]["category"],
            cwe_id=cwe_id,
            data=defect_data,
        )

        # Extra
        self.severity = self.data["extra"]["severity"]
        self.lines = self.data["extra"]["lines"]


class SemgrepAnalysisResult(AnalysisResult):
    def __init__(self, result_dir: str, result_data: dict, cmdout: dict) -> None:
        super().__init__(
            name=os.path.basename(result_dir),
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

        if match := re.search(r"• Parsed lines: ~([\d\.]+)%", cmdout["logs"]):
            self.coverage = float(match.groups()[0]) / 100
            self.loc = int(self.coverage * cmdout["loc"])

    @classmethod
    def load_from_result_dir(cls, result_dir: str) -> Self:
        # Cmdout
        with open(os.path.join(result_dir, "sastb_cmdout.json")) as f:
            cmdout = json.load(f)

        # Analysis outputs
        analysis_output_path = os.path.join(result_dir, "output.json")
        if os.path.isfile(analysis_output_path):
            analysis_output = json.load(open(analysis_output_path, "r"))
        else:
            raise MissingFile(["output.json"])

        return cls(result_dir, analysis_output, cmdout)
