from abc import ABC, abstractmethod
from typing import Any, Self


class Defect:
    def __init__(
        self, file: str, checker: str, category: str, cwe_id: int, data: tuple[Any]
    ) -> None:
        self.file = file
        self.checker = checker
        self.category = category
        self.cwe_id = cwe_id
        self.data = data

    def __repr__(self) -> str:
        return f"""{self.__class__.__name__}(
    file: \t{self.file}
    checker: \t{self.checker}
    category: \t{self.category}
    cwe_id: \t{self.cwe_id}
)"""


class AnalysisResult(ABC):
    def __init__(
        self,
        name: str,
        lang: str,
        files: list[str],
        defects: list[Defect],
        time: float,
        loc: int,
        data: tuple[Any],
    ) -> None:
        self.name = name
        self.lang = lang
        self.files = files
        self.defects = defects
        self.time = time
        self.loc = loc
        self.data = data

    def __repr__(self) -> str:
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
    def load_from_result_dir(cls, result_dir: str) -> Self:
        pass

    @classmethod
    def load_from_result_dirs(cls, result_dirs: str) -> list[Self]:
        analysis_results = []
        for result_dir in result_dirs:
            analysis_results.append(cls.load_from_result_dir(result_dir))
        return analysis_results

    def checker_to_category(self, checker: str) -> str:
        for defect in self.defects:
            if checker == defect.checker:
                return defect.category
        return "NONE"

    def stats_by_checkers(self) -> dict:
        stats = {}
        for defect in self.defects:
            if defect.checker not in stats.keys():
                stats[defect.checker] = {"count": 1, "files": {defect.file}}
            else:
                stats[defect.checker]["files"].add(defect.file)
                stats[defect.checker]["count"] = len(stats[defect.checker]["files"])

        return stats

    def stats_by_categories(self) -> dict:
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
        stats = {}
        for defect in self.defects:
            if defect.file not in stats.keys():
                stats[defect.file] = {"count": 1, "checkers": {defect.checker}}
            else:
                stats[defect.file]["checkers"].add(defect.checker)
                stats[defect.file]["count"] = len(stats[defect.file]["checkers"])

        return stats

    def stats_by_cwes(self) -> dict:
        stats = {}
        for defect in self.defects:
            if defect.cwe_id not in stats.keys():
                stats[defect.cwe_id] = {"count": 1, "files": {defect.file}}
            else:
                stats[defect.cwe_id]["files"].add(defect.file)
                stats[defect.cwe_id]["count"] = len(stats[defect.cwe]["files"])

        return stats
