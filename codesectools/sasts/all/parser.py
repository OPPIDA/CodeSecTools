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
        """Initialize an AllSASTAnalysisResult instance.

        Args:
            name: The name of the project.
            analysis_results: A dictionary of analysis results from various SAST tools.

        """
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
                stats[defect.filepath_str] = {"count": 1, "sasts": [defect.sast_name]}
            else:
                stats[defect.filepath_str]["sasts"].append(defect.sast_name)
                stats[defect.filepath_str]["count"] += 1

        return stats

    def stats_by_sasts(self) -> dict:
        """Calculate statistics on defects, grouped by SAST tool."""
        stats = {}
        for defect in self.defects:
            if defect.sast_name not in stats.keys():
                stats[defect.sast_name] = {"count": 1}
            else:
                stats[defect.sast_name]["count"] += 1

        return stats

    def stats_by_levels(self) -> dict:
        """Calculate statistics on defects, grouped by severity level."""
        stats = {}
        for defect in self.defects:
            if defect.level not in stats.keys():
                stats[defect.level] = {"count": 0, "sast_counts": {}}

            stats[defect.level]["count"] += 1
            sast_counts = stats[defect.level]["sast_counts"]
            sast_counts[defect.sast_name] = sast_counts.get(defect.sast_name, 0) + 1
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
                    "sast_counts": {defect.sast_name: 1},
                }
            else:
                stats[defect.cwe]["count"] += 1
                if defect.filepath_str not in stats[defect.cwe]["files"]:
                    stats[defect.cwe]["files"].append(defect.filepath_str)
                stats[defect.cwe]["sast_counts"][defect.sast_name] = (
                    stats[defect.cwe]["sast_counts"].get(defect.sast_name, 0) + 1
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

            same_cwe = 0
            for cwe in defects_cwes:
                cwes_sasts = {d.sast_name for d in defects if d.cwe == cwe}
                if set(self.sast_names) == cwes_sasts:
                    same_cwe += 1
                else:
                    same_cwe += (len(set(self.sast_names) & cwes_sasts) - 1) / len(
                        self.sast_names
                    )

            defects_severity = []
            defect_locations = {}
            for defect in defects:
                defects_severity.append(
                    {"error": 1, "warning": 0.5, "note": 0.25, "none": 0.125}[
                        defect.level
                    ]
                )

                for line in defect.lines:
                    if not defect_locations.get(line):
                        defect_locations[line] = []
                    defect_locations[line].append(defect)

            same_location = 0
            same_location_same_cwe = 0
            for _, defects_ in defect_locations.items():
                same_location_coeff = 0
                if set(defect.sast_name for defect in defects_) == set(self.sast_names):
                    same_location_coeff = 1
                else:
                    same_location_coeff = (
                        len(
                            set(defect.sast_name for defect in defects_)
                            & set(self.sast_names)
                        )
                        - 1
                    ) / len(set(self.sast_names))
                same_location += same_location_coeff

                defects_by_cwe = {}
                for defect in defects_:
                    if not defects_by_cwe.get(defect.cwe):
                        defects_by_cwe[defect.cwe] = []
                    defects_by_cwe[defect.cwe].append(defect)

                for _, defects_ in defects_by_cwe.items():
                    if set(defect.sast_name for defect in defects_) == set(
                        self.sast_names
                    ):
                        same_location_same_cwe += same_location_coeff * 1
                    else:
                        same_location_same_cwe += (
                            same_location_coeff
                            * (
                                len(
                                    set(defect.sast_name for defect in defects_)
                                    & set(self.sast_names)
                                )
                                - 1
                            )
                            / len(self.sast_names)
                        )

            stats[defect_file] = {
                "score": {
                    "severity": sum(defects_severity) / len(defects_severity),
                    "same_cwe": same_cwe * 2,
                    "same_location": same_location * 4,
                    "same_location_same_cwe": same_location_same_cwe * 8,
                },
            }
        return stats

    def prepare_report_data(self) -> dict:
        """Prepare data needed to generate a report."""
        report = {}
        scores = self.stats_by_scores()

        defect_files = {}
        for defect in self.defects:
            if defect.filepath_str not in defect_files:
                defect_files[defect.filepath_str] = []
            defect_files[defect.filepath_str].append(defect)

        for defect_file, defects in defect_files.items():
            locations = []
            for defect in defects:
                for group in group_successive(defect.lines):
                    start, end = group[0], group[-1]
                    locations.append(
                        (defect.sast_name, defect.cwe, defect.message, (start, end))
                    )

            report[defect_file] = {
                "score": sum(v for v in scores[defect_file]["score"].values()),
                "source_path": str(self.source_path / defect.filepath),
                "locations": locations,
                "defects": defects,
            }

        report = {
            k: v
            for k, v in sorted(
                report.items(),
                key=lambda item: item[1]["score"],
                reverse=True,
            )
        }

        return report
