from utils import *


## Base class
class Defect:
    def __init__(self, file, checker, category, cwe_id, data):
        self.file = file
        self.checker = checker
        self.category = category
        self.cwe_id = cwe_id
        self.data = data

    def __repr__(self):
        return f"""{self.__class__.__name__}(
    file: \t{self.file}
    checker: \t{self.checker}
    category: \t{self.category}
    cwe_id: \t{self.cwe_id}
)"""


class AnalysisResult:
    def __init__(self, name, lang, files, defects, time, data):
        self.name = name
        self.lang = lang
        self.files = files
        self.defects = defects
        self.time = time
        self.data = data

    def __repr__(self):
        return f"""{self.__class__.__name__}(
    name: \t{self.name}
    lang: \t{self.lang}
    files: \t{self.files}
    file_count: \t{len(self.files)}
    defect_count: \t{len(self.defects)}
    time: \t{self.time}
)"""

    def stats_by_checkers(self):
        stats = {}
        for defect in self.defects:
            if defect.checker not in stats.keys():
                stats[defect.checker] = {"count": 1, "files": {defect.file}}
            else:
                stats[defect.checker]["files"].add(defect.file)
                stats[defect.checker]["count"] = len(stats[defect.checker]["files"])

        return stats

    def stats_by_categories(self):
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

    def stats_by_files(self):
        stats = {}
        for defect in self.defects:
            if defect.file not in stats.keys():
                stats[defect.file] = {"count": 1, "checkers": {defect.checker}}
            else:
                stats[defect.file]["checkers"].add(defect.checker)
                stats[defect.file]["count"] = len(stats[defect.file]["checkers"])

        return stats

    def stats_by_cwes(self):
        stats = {}
        for defect in self.defects:
            if defect.cwe_id not in stats.keys():
                stats[defect.cwe_id] = {"count": 1, "files": {defect.file}}
            else:
                stats[defect.cwe_id]["files"].add(defect.file)
                stats[defect.cwe_id]["count"] = len(stats[defect.cwe]["files"])

        return stats


## Common helpers
def list_results(
    result_dir, supported_dataset, project=False, dataset=False, limit=None
):
    # TODO: limit
    result_dirs = []
    if os.path.isdir(result_dir):
        for child in os.listdir(result_dir):
            child_path = os.path.join(result_dir, child)
            if os.path.isdir(child_path):
                if child in supported_dataset and dataset:
                    result_dirs.append(child)
                elif child not in supported_dataset and project:
                    result_dirs.append(child)

    result_dirs = sorted(result_dirs)
    return result_dirs
