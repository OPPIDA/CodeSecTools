"""Provides classes for generating plots and visualizations from aggregated SAST results."""

import matplotlib.pyplot as plt
from matplotlib.figure import Figure

from codesectools.sasts.all.sast import AllSAST
from codesectools.sasts.core.graphics import Graphics as CoreGraphics
from codesectools.utils import shorten_path


class Graphics(CoreGraphics):
    """Base class for generating plots for aggregated SAST results.

    Attributes:
        project_name (str): The name of the project being visualized.
        all_sast (AllSAST): The instance managing all SAST tools.
        output_dir (Path): The directory containing the aggregated results.
        color_mapping (dict): A dictionary mapping SAST tool names to colors.
        sast_names (list[str]): A list of names of the SAST tools involved in the analysis.
        plot_functions (list): A list of methods responsible for generating plots.

    """

    def __init__(self, project_name: str) -> None:
        """Initialize the Graphics object."""
        self.project_name = project_name
        self.all_sast = AllSAST()
        self.output_dir = self.all_sast.output_dir / project_name
        self.color_mapping = {}
        cmap = plt.get_cmap("Set2")
        self.sast_names = []
        for i, sast in enumerate(self.all_sast.sasts):
            if self.project_name in sast.list_results(project=True):
                self.color_mapping[sast.name] = cmap(i)
                self.sast_names.append(sast.name)
        self.plot_functions = []


## Single project
class ProjectGraphics(Graphics):
    """Generate graphics for an aggregated analysis result of a single project."""

    def __init__(self, project_name: str) -> None:
        """Initialize the ProjectGraphics object."""
        super().__init__(project_name=project_name)
        self.result = self.all_sast.parser.load_from_output_dir(project_name)
        self.plot_functions.extend(
            [self.plot_overview, self.plot_top_cwes, self.plot_top_scores]
        )

    def plot_overview(self) -> Figure:
        """Generate an overview plot with stats by files, SAST tools, and categories."""
        fig, (ax1, ax2, ax3) = plt.subplots(1, 3, layout="constrained")
        by_files = self.result.stats_by_files()
        by_sasts = self.result.stats_by_sasts()
        by_categories = self.result.stats_by_categories()

        # Plot by files
        X_files, Y_files = [], []
        sorted_files = sorted(
            list(by_files.items()), key=lambda e: e[1]["count"], reverse=True
        )
        for k, v in sorted_files[: self.limit]:
            X_files.append(shorten_path(k))
            Y_files.append(v["count"])

            COLORS_COUNT = {v: 0 for k, v in self.color_mapping.items()}

            for sast in v["sasts"]:
                color = self.color_mapping[sast]
                COLORS_COUNT[color] += 1

            bars = []
            current_height = 0
            for color, height in COLORS_COUNT.items():
                if height > 0:
                    bars.append((shorten_path(k), current_height + height, color))
                    current_height += height

            for k_short, height, color in bars[::-1]:
                ax1.bar(k_short, height, color=color)

        ax1.set_xticks(X_files, X_files, rotation=45, ha="right")
        ax1.set_title(f"Stats by files (limit to {self.limit})")

        # Plot by sasts
        X_sasts, Y_checkers = [], []
        sorted_checkers = sorted(
            list(by_sasts.items()), key=lambda e: e[1]["count"], reverse=True
        )
        for k, v in sorted_checkers[: self.limit]:
            X_sasts.append(k)
            Y_checkers.append(v["count"])

        ax2.bar(
            X_sasts,
            Y_checkers,
            color=[self.color_mapping[s] for s in X_sasts],
        )
        ax2.set_xticks(X_sasts, X_sasts, rotation=45, ha="right")
        ax2.set_title("Stats by SAST tools")

        # Plot by categories
        X_categories = ["HIGH", "MEDIUM", "LOW"]
        for category in X_categories:
            if not by_categories.get(category):
                continue

            sast_counts = by_categories[category]["sast_counts"]

            bars = []
            current_height = 0
            for sast_name, count in sorted(sast_counts.items()):
                color = self.color_mapping[sast_name]
                height = count
                if height > 0:
                    bars.append((category, current_height + height, color))
                    current_height += height

            for category_name, height, color in bars[::-1]:
                ax3.bar(category_name, height, color=color)

        ax3.set_xticks(X_categories, X_categories, rotation=45, ha="right")
        ax3.set_title("Stats by categories")

        fig.suptitle(
            f"Project {self.project_name}, {len(self.result.files)} files analyzed, {len(self.result.defects)} defects raised",
            fontsize=16,
        )
        labels = list(self.color_mapping.keys())
        handles = [
            plt.Rectangle((0, 0), 1, 1, color=self.color_mapping[label])
            for label in labels
        ]
        plt.legend(handles, labels)

        return fig

    def plot_top_cwes(self) -> Figure:
        """Generate a stacked bar plot for the top CWEs found."""
        fig, ax = plt.subplots(1, 1, layout="constrained")
        by_cwes = self.result.stats_by_cwes()

        sorted_cwes = sorted(
            list(by_cwes.items()), key=lambda item: item[1]["count"], reverse=True
        )

        X_cwes, cwe_data = [], []
        for cwe, data in sorted_cwes[: self.limit]:
            X_cwes.append(f"{cwe.name}")
            cwe_data.append(data)

        bottoms = [0] * len(X_cwes)

        for sast_name in self.sast_names:
            sast_counts = [data["sast_counts"].get(sast_name, 0) for data in cwe_data]

            ax.bar(
                X_cwes,
                sast_counts,
                bottom=bottoms,
                label=sast_name,
                color=self.color_mapping.get(sast_name),
            )
            bottoms = [b + c for b, c in zip(bottoms, sast_counts, strict=False)]

        ax.set_xticks(range(len(X_cwes)), X_cwes, rotation=45, ha="right")
        ax.set_title(f"Top {self.limit} CWEs by Defect Count")
        ax.set_ylabel("Number of Defects")
        ax.legend(title="SAST tools")
        fig.suptitle(f"CWE Statistics for project {self.project_name}", fontsize=16)

        return fig

    def plot_top_scores(self) -> Figure:
        """Generate a stacked bar plot for files with the highest scores."""
        fig, ax = plt.subplots(1, 1, layout="constrained")
        by_scores = self.result.stats_by_scores()

        for file, data in by_scores.items():
            by_scores[file]["total_score"] = sum(data["score"].values())

        sorted_files = sorted(
            list(by_scores.items()),
            key=lambda item: item[1]["total_score"],
            reverse=True,
        )

        X_files, score_data = [], []
        for file, data in sorted_files[: self.limit]:
            X_files.append(shorten_path(file))
            score_data.append(data["score"])

        score_keys = score_data[0].keys()
        score_colors = plt.get_cmap("Set2", len(score_keys))
        bottoms = [0] * len(X_files)

        for i, key in enumerate(score_keys):
            key_values = [data.get(key, 0) for data in score_data]
            ax.bar(
                X_files,
                key_values,
                bottom=bottoms,
                label=f"{key.replace('_', ' ').title()} (x{2**i})",
                color=score_colors(i),
            )
            bottoms = [b + v for b, v in zip(bottoms, key_values, strict=False)]

        ax.set_xticks(range(len(X_files)), X_files, rotation=45, ha="right")
        ax.set_title(f"Top {self.limit} Files by Score")
        ax.set_ylabel("Score")
        ax.legend(title="Score Components")
        fig.suptitle(f"File Scores for project {self.project_name}", fontsize=16)

        return fig
