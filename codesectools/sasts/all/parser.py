"""Provides classes for parsing and aggregating results from multiple SAST tools."""

from typing import TYPE_CHECKING, Self

from codesectools.sasts import SASTS_ALL
from codesectools.sasts.core.parser import AnalysisResult
from codesectools.utils import group_successive

if TYPE_CHECKING:
    from codesectools.sasts.core.sast import SAST


class AllSASTAnalysisResult:
    """Represent the aggregated results from multiple SAST analyses on a single project."""

    def __init__(self, name: str, analysis_results: dict[str, AnalysisResult]) -> None:
        """Initialize an AllSASTAnalysisResult instance."""
        self.name = name
        self.source_path = None
        self.analysis_results = analysis_results
        self.lang = None
        self.sast_names = []
        self.files = set()
        self.defects = []

        for sast_name, analysis_result in self.analysis_results.items():
            if not self.lang and not self.source_path:
                self.lang = analysis_result.lang
                self.source_path = analysis_result.source_path
            else:
                assert analysis_result.lang == self.lang
                assert analysis_result.source_path == self.source_path
            self.sast_names.append(sast_name)
            self.files |= set(analysis_result.files)
            self.defects += analysis_result.defects

        self.category_mapping = {}
        for sast_name in self.sast_names:
            sast = SASTS_ALL[sast_name]["sast"]
            for category_name, color in sast.color_mapping.items():
                if color.lower() == "red":
                    self.category_mapping[(sast_name, category_name)] = "HIGH"
                elif color.lower() == "orange":
                    self.category_mapping[(sast_name, category_name)] = "MEDIUM"
                elif color.lower() == "yellow":
                    self.category_mapping[(sast_name, category_name)] = "LOW"

        for defect in self.defects:
            defect.category = self.category_mapping.get(
                (defect.sast, defect.category), "LOW"
            )

    def __repr__(self) -> str:
        """Return a developer-friendly string representation of the aggregated result."""
        return f"""{self.__class__.__name__}(
    name: \t{self.name}
    lang: \t{self.lang}
    sasts: \t{self.sast_names}
    file_count: \t{len(self.files)}
    defect_count: \t{len(self.defects)}
)"""

    @classmethod
    def load_from_output_dir(cls, project_name: str) -> Self:
        """Load and parse analysis results from all SAST tools for a given project."""
        analysis_results = {}
        for sast_name, sast_data in SASTS_ALL.items():
            sast_instance: SAST = sast_data["sast"]()
            output_dir = sast_instance.output_dir / project_name
            if output_dir.is_dir():
                analysis_results[sast_name] = sast_instance.parser.load_from_output_dir(
                    output_dir=output_dir
                )
        return cls(name=project_name, analysis_results=analysis_results)

    def stats_by_files(self) -> dict:
        """Calculate statistics on defects, grouped by file."""
        stats = {}
        for defect in self.defects:
            if defect.filepath_str not in stats.keys():
                stats[defect.filepath_str] = {"count": 1, "sasts": [defect.sast]}
            else:
                stats[defect.filepath_str]["sasts"].append(defect.sast)
                stats[defect.filepath_str]["count"] += 1

        return stats

    def stats_by_sasts(self) -> dict:
        """Calculate statistics on defects, grouped by SAST tool."""
        stats = {}
        for defect in self.defects:
            if defect.sast not in stats.keys():
                stats[defect.sast] = {"count": 1}
            else:
                stats[defect.sast]["count"] += 1

        return stats

    def stats_by_categories(self) -> dict:
        """Calculate statistics on defects, grouped by severity category."""
        stats = {}
        for defect in self.defects:
            if defect.category not in stats.keys():
                stats[defect.category] = {"count": 0, "sast_counts": {}}

            stats[defect.category]["count"] += 1
            sast_counts = stats[defect.category]["sast_counts"]
            sast_counts[defect.sast] = sast_counts.get(defect.sast, 0) + 1
        return stats

    def stats_by_cwes(self) -> dict:
        """Calculate statistics on defects, grouped by CWE."""
        stats = {}
        for defect in self.defects:
            if defect.cwe.id == -1:
                continue

            if defect.cwe not in stats:
                stats[defect.cwe] = {
                    "count": 1,
                    "files": [defect.filepath_str],
                    "sast_counts": {defect.sast: 1},
                }
            else:
                stats[defect.cwe]["count"] += 1
                if defect.filepath_str not in stats[defect.cwe]["files"]:
                    stats[defect.cwe]["files"].append(defect.filepath_str)
                stats[defect.cwe]["sast_counts"][defect.sast] = (
                    stats[defect.cwe]["sast_counts"].get(defect.sast, 0) + 1
                )
        return stats

    def stats_by_scores(self) -> dict:
        """Calculate a risk score for each file based on defect data."""
        defect_files = {}
        for defect in self.defects:
            if defect.filepath_str not in defect_files:
                defect_files[defect.filepath_str] = []
            defect_files[defect.filepath_str].append(defect)

        stats = {}
        for defect_file, defects in defect_files.items():
            defects_cwes = {d.cwe for d in defects if d.cwe.id != -1}

            defects_same_cwe = 0
            for cwe in defects_cwes:
                cwes_sasts = {d.sast for d in defects if d.cwe == cwe}
                if set(self.sast_names) == cwes_sasts:
                    defects_same_cwe += 1
                else:
                    defects_same_cwe += (
                        len(set(self.sast_names) & cwes_sasts) - 1
                    ) / len(self.sast_names)

            defect_locations = {}
            for defect in defects:
                for line in defect.lines:
                    if not defect_locations.get(line):
                        defect_locations[line] = []
                    defect_locations[line].append(defect)

            defects_same_location = 0
            defects_same_location_same_cwe = 0
            for _, defects_ in defect_locations.items():
                if set(defect.sast for defect in defects_) == set(self.sast_names):
                    defects_same_location += 1
                    defects_by_cwe = {}
                    for defect in defects_:
                        if not defects_by_cwe.get(defect.cwe):
                            defects_by_cwe[defect.cwe] = []
                        defects_by_cwe[defect.cwe].append(defect)

                    for _, defects_ in defects_by_cwe.items():
                        if set(defect.sast for defect in defects_) == set(
                            self.sast_names
                        ):
                            defects_same_location_same_cwe += 1
                        else:
                            defects_same_location_same_cwe += (
                                len(
                                    set(defect.sast for defect in defects_)
                                    & set(self.sast_names)
                                )
                                - 1
                            ) / len(self.sast_names)

            stats[defect_file] = {
                "score": {
                    "defect_number": len(defects),
                    "defects_same_cwe": defects_same_cwe * 2,
                    "defects_same_location": defects_same_location * 4,
                    "defects_same_location_same_cwe": defects_same_location_same_cwe
                    * 8,
                },
            }

        return stats

    def prepare_report_data(self) -> dict:
        """Prepare data needed to generate a report."""
        report = {"score": {}, "defects": {}}
        scores = self.stats_by_scores()

        report["score"] = {k: 0 for k, _ in list(scores.values())[0]["score"].items()}

        defect_files = {}
        for defect in self.defects:
            if defect.filepath_str not in defect_files:
                defect_files[defect.filepath_str] = []
            defect_files[defect.filepath_str].append(defect)

        for defect_file, defects in defect_files.items():
            for k, v in scores[defect_file]["score"].items():
                report["score"][k] += v

            locations = []
            for defect in defects:
                for group in group_successive(defect.lines):
                    start, end = group[0], group[-1]
                    locations.append(
                        (defect.sast, defect.cwe, defect.message, (start, end))
                    )

            report["defects"][defect_file] = {
                "score": scores[defect_file]["score"],
                "source_path": str(self.source_path / defect.filepath),
                "locations": locations,
                "raw": defects,
            }

        report["defects"] = {
            k: v
            for k, v in sorted(
                report["defects"].items(),
                key=lambda item: (sum(v for v in item[1]["score"].values())),
                reverse=True,
            )
        }

        return report
