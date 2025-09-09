"""Provides classes for parsing and aggregating results from multiple SAST tools."""

from typing import TYPE_CHECKING, Self

from codesectools.sasts import SASTS_ALL
from codesectools.sasts.core.parser import AnalysisResult

if TYPE_CHECKING:
    from codesectools.sasts.core.sast import SAST


class AllSASTAnalysisResult:
    """Represent the aggregated results from multiple SAST analyses on a single project."""

    def __init__(self, name: str, analysis_results: dict[str, AnalysisResult]) -> None:
        """Initialize an AllSASTAnalysisResult instance."""
        self.name = name
        self.analysis_results = analysis_results
        self.lang = None
        self.sasts = []
        self.files = set()
        self.defects = []

        for sast_name, analysis_result in self.analysis_results.items():
            if not self.lang:
                self.lang = analysis_result.lang
            else:
                assert analysis_result.lang == self.lang
            self.sasts.append(sast_name)
            self.files |= set(analysis_result.files)
            self.defects += analysis_result.defects

        self.category_mapping = {}
        for sast_name in self.sasts:
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
                (defect.sast, defect.category), "NONE"
            )

    def __repr__(self) -> str:
        """Return a developer-friendly string representation of the aggregated result."""
        return f"""{self.__class__.__name__}(
    name: \t{self.name}
    lang: \t{self.lang}
    sasts: \t{self.sasts}
    file_count: \t{len(self.files)}
    defect_count: \t{len(self.defects)}
)"""

    @classmethod
    def load_from_output_dir(cls, project_name: str) -> Self:
        """Load and parse analysis results from all SASTs for a given project."""
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
            if defect.file not in stats.keys():
                stats[defect.file] = {"count": 1, "sasts": [defect.sast]}
            else:
                stats[defect.file]["sasts"].append(defect.sast)
                stats[defect.file]["count"] += 1

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
                    "files": [defect.file],
                    "sast_counts": {defect.sast: 1},
                }
            else:
                stats[defect.cwe]["count"] += 1
                if defect.file not in stats[defect.cwe]["files"]:
                    stats[defect.cwe]["files"].append(defect.file)
                stats[defect.cwe]["sast_counts"][defect.sast] = (
                    stats[defect.cwe]["sast_counts"].get(defect.sast, 0) + 1
                )
        return stats

    def stats_by_scores(self) -> dict:
        """Calculate a risk score for each file based on defect data."""
        defect_files = {}
        for defect in self.defects:
            if defect.file not in defect_files:
                defect_files[defect.file] = []
            defect_files[defect.file].append(defect)

        stats = {}
        for defect_file, defects in defect_files.items():
            base_score = len(defects)
            defects_cwes = {d.cwe for d in defects if d.cwe.id != -1}

            all_sasts_cwes = 0
            if self.sasts:
                for cwe in defects_cwes:
                    cwes_sasts = {d.sast for d in defects if d.cwe == cwe}
                    if set(self.sasts) == cwes_sasts:
                        all_sasts_cwes += len([d for d in defects if d.cwe == cwe])

            stats[defect_file] = {
                "score": {
                    "base_score": base_score,
                    "unique_cwes_number": len(defects_cwes),
                    "all_sasts_cwes": base_score * all_sasts_cwes,
                }
            }
        return stats
