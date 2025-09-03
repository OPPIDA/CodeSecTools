"""Provides classes for generating plots and visualizations from analysis results.

This module contains base and specific graphics classes that use Matplotlib to create
visual representations of SAST analysis data, such as defect distributions and
benchmark performance.
"""

import shutil
import tempfile

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import typer
from matplotlib.figure import Figure
from rich import print

from codesectools.datasets.core.dataset import FileDataset, GitRepoDataset
from codesectools.sasts.core.sast.sast import SAST
from codesectools.shared.cwe import CWE

## Matplotlib config
matplotlib.rcParams.update(
    {
        "font.family": "serif",
        "font.size": 11,
    }
)


class Graphics:
    """Base class for generating graphics from SAST results.

    Attributes:
        sast (SAST): The SAST tool instance.
        output_dir (Path): The directory containing the analysis results.
        color_mapping (dict): A mapping of categories to colors for plotting.
        plot_functions (list): A list of methods that generate plots.
        limit (int): The maximum number of items to show in top-N plots.
        has_latex (bool): True if a LaTeX installation is found.

    """

    def __init__(self, sast: SAST, project_name: str) -> None:
        """Initialize the Graphics object.

        Args:
            sast: The SAST tool instance.
            project_name: The name of the project or dataset being visualized.

        """
        self.sast = sast
        self.output_dir = sast.output_dir / project_name
        self.color_mapping = sast.color_mapping
        self.color_mapping["NONE"] = "BLACK"
        self.plot_functions = []

        # Plot options
        self.limit = 10

        self.has_latex = shutil.which("pdflatex")
        if self.has_latex:
            matplotlib.use("pgf")
            matplotlib.rcParams.update(
                {
                    "pgf.texsystem": "pdflatex",
                    "text.usetex": True,
                    "pgf.rcfonts": False,
                }
            )
        else:
            print("pdflatex not found, pgf will not be generated")

    def export(self, overwrite: bool, pgf: bool, show: bool) -> None:
        """Generate, save, and optionally display all registered plots.

        Args:
            overwrite: If True, overwrite existing figure files.
            pgf: If True and LaTeX is available, export figures in PGF format.
            show: If True, open the generated figures using the default viewer.

        """
        for plot_function in self.plot_functions:
            fig = plot_function()
            fig_name = plot_function.__name__.replace("plot_", "")
            fig.set_size_inches(12, 7)

            if show:
                with tempfile.NamedTemporaryFile(delete=True) as temp:
                    fig.savefig(f"{temp.name}.png", bbox_inches="tight")
                    typer.launch(f"{temp.name}.png", wait=False)

            figure_dir = self.output_dir / "_figures"
            figure_dir.mkdir(exist_ok=True, parents=True)
            figure_path = figure_dir / f"{fig_name}.png"
            if figure_path.is_file() and not overwrite:
                if not typer.confirm(
                    f"Found existing figure at {figure_path}, would you like to overwrite?"
                ):
                    print(f"Figure {fig_name} not saved")
                    continue

            fig.savefig(figure_path, bbox_inches="tight")
            print(f"Figure {fig_name} saved at {figure_path}")

            if pgf and self.has_latex:
                figure_path_pgf = figure_dir / f"{fig_name}.pgf"
                fig.savefig(figure_path_pgf, bbox_inches="tight")
                print(f"Figure {fig_name} exported to pgf")


## Single project
class ProjectGraphics(Graphics):
    """Generate graphics for a single project analysis result.

    Attributes:
        result (AnalysisResult): The loaded analysis result data.

    """

    def __init__(self, sast: SAST, project_name: str) -> None:
        """Initialize the ProjectGraphics object.

        Args:
            sast: The SAST tool instance.
            project_name: The name of the project.

        """
        super().__init__(sast=sast, project_name=project_name)
        self.result = sast.parser.load_from_output_dir(self.output_dir)
        self.plot_functions.extend([self.plot_overview])

    def checker_to_category(self, checker: str) -> str:
        """Map a checker name to its category.

        Args:
            checker: The name of the checker.

        Returns:
            The category string for the checker, or "NONE" if not found.

        """
        return self.result.checker_to_category(checker)

    def plot_overview(self) -> Figure:
        """Generate an overview plot with stats by files, checkers, and categories.

        Returns:
            A Matplotlib Figure object containing the plots.

        """
        project_name = self.result.name

        fig, (ax1, ax2, ax3) = plt.subplots(1, 3, layout="constrained")
        by_files = self.result.stats_by_files()
        by_checkers = self.result.stats_by_checkers()
        by_categories = self.result.stats_by_categories()

        # Plot by files
        X_files, Y_files = [], []
        sorted_files = sorted(
            list(by_files.items()), key=lambda e: e[1]["count"], reverse=True
        )
        for k, v in sorted_files[: self.limit]:
            X_files.append(k)
            Y_files.append(v["count"])

            COLORS_COUNT = {v: 0 for k, v in self.color_mapping.items()}

            for checker in v["checkers"]:
                category = self.checker_to_category(checker)
                color = self.color_mapping[category]
                COLORS_COUNT[color] += 1

            bars = []
            current_height = 0
            for color, height in COLORS_COUNT.items():
                if height > 0:
                    bars.append((k, current_height + height, color))
                    current_height += height

            for k, height, color in bars[::-1]:
                ax1.bar(k, height, color=color)

        ax1.set_xticks(X_files, X_files, rotation=45, ha="right")
        ax1.set_title(f"Stats by files (limit to {self.limit})")

        # Plot by checkers
        X_checkers, Y_checkers = [], []
        sorted_checkers = sorted(
            list(by_checkers.items()), key=lambda e: e[1]["count"], reverse=True
        )
        for k, v in sorted_checkers[: self.limit]:
            X_checkers.append(k)
            Y_checkers.append(v["count"])

        ax2.bar(
            X_checkers,
            Y_checkers,
            color=[self.color_mapping[self.checker_to_category(c)] for c in X_checkers],
        )
        ax2.set_xticks(X_checkers, X_checkers, rotation=45, ha="right")
        ax2.set_title(f"Stats by checkers (limit to {self.limit})")

        # Plot by categories
        X_categories, Y_categories = [], []
        sorted_categories = sorted(
            list(by_categories.items()), key=lambda e: e[1]["count"], reverse=True
        )
        for k, v in sorted_categories[: self.limit]:
            X_categories.append(k)
            Y_categories.append(v["count"])

        ax3.bar(
            X_categories,
            Y_categories,
            color=[self.color_mapping[self.checker_to_category(c)] for c in X_checkers],
        )
        ax3.set_xticks(X_categories, X_categories, rotation=45, ha="right")
        ax3.set_title(f"Stats by categories (limit to {self.limit})")

        fig.suptitle(
            f"Project {project_name}, {len(self.result.files)} files analyzed, {len(self.result.defects)} defects raised",
            fontsize=16,
        )
        labels = list(self.color_mapping.keys())
        handles = [
            plt.Rectangle((0, 0), 1, 1, color=self.color_mapping[label])
            for label in labels
        ]
        plt.legend(handles, labels)

        return fig


## Datasets
class FileDatasetGraphics(ProjectGraphics):
    """Generate graphics for a file-based dataset benchmark result.

    Attributes:
        dataset (FileDataset): The dataset instance used for the benchmark.
        benchmark_data (FileDatasetData): The validated benchmark data.

    """

    def __init__(self, sast: SAST, dataset: FileDataset) -> None:
        """Initialize the FileDatasetGraphics object.

        Args:
            sast: The SAST tool instance.
            dataset: The file-based dataset that was benchmarked.

        """
        super().__init__(sast=sast, project_name=dataset.full_name)
        self.dataset = dataset
        self.benchmark_data = self.dataset.validate(self.result)
        self.plot_functions.extend([self.plot_top_cwes])

    def plot_top_cwes(self) -> Figure:
        """Generate a plot showing the top predicted CWEs.

        Returns:
            A Matplotlib Figure object containing the plot.

        """
        b = self.benchmark_data
        fig, ax = plt.subplots(1, 1, layout="constrained")
        cwe_counter: dict[CWE, dict[str, int]] = {}

        def init_cwe_counter(cwe: CWE) -> None:
            if cwe not in cwe_counter:
                cwe_counter[cwe] = {"tp": 0, "fp": 0, "fn": 0}

        for cwe in b.tp_cwes:
            init_cwe_counter(cwe)
            cwe_counter[cwe]["tp"] += 1

        for cwe in b.fp_cwes:
            init_cwe_counter(cwe)
            cwe_counter[cwe]["fp"] += 1

        for cwe in b.fn_cwes:
            init_cwe_counter(cwe)
            cwe_counter[cwe]["fn"] += 1

        X, Y1, Y2, Y3 = [], [], [], []
        # Sort by TP, then FN, then FP
        sorted_cwes = sorted(
            list(cwe_counter.items()),
            key=lambda i: (
                i[1]["tp"],
                i[1]["fn"],
                i[1]["fp"],
            ),
            reverse=True,
        )

        for cwe, v in sorted_cwes[: self.limit]:
            X.append(f"{cwe.name} (ID: {cwe.id})")
            Y1.append(v["tp"])
            Y2.append(v["fp"])
            Y3.append(v["fn"])

        ax.set_xticks(range(len(X)), X, rotation=45, ha="right")
        ax.set_xticklabels(X)
        ax.set_yscale("log")
        width = 0.25
        bars1 = ax.bar(
            [i - width for i in range(len(X))],
            Y1,
            width=width,
            label="True Positives",
            color="green",
        )
        bars2 = ax.bar(
            [i for i in range(len(X))],
            Y2,
            width=width,
            label="False Positives",
            color="orange",
        )
        bars3 = ax.bar(
            [i + width for i in range(len(X))],
            Y3,
            width=width,
            label="False Negatives",
            color="red",
        )
        ax.bar_label(bars1, padding=0)
        ax.bar_label(bars2, padding=0)
        ax.bar_label(bars3, padding=0)
        plt.legend()
        fig.suptitle("TOP predicted CWEs")
        return fig


class GitRepoDatasetGraphics(Graphics):
    """Generate graphics for a Git repository-based dataset benchmark result.

    Attributes:
        dataset (GitRepoDataset): The dataset instance used for the benchmark.
        results (list[AnalysisResult]): A list of loaded analysis results.
        benchmark_data (GitRepoDatasetData): The validated benchmark data.

    """

    def __init__(self, sast: SAST, dataset: GitRepoDataset) -> None:
        """Initialize the GitRepoDatasetGraphics object.

        Args:
            sast: The SAST tool instance.
            dataset: The Git repository-based dataset that was benchmarked.

        """
        super().__init__(sast=sast, project_name=dataset.full_name)
        self.dataset = dataset
        analyzed_repo = {repo.name for repo in dataset.repos} & set(
            dir.name for dir in self.output_dir.iterdir()
        )
        repo_paths = [self.output_dir / repo_name for repo_name in analyzed_repo]
        self.results = sast.parser.load_from_output_dirs(repo_paths)
        self.benchmark_data = self.dataset.validate(self.results)
        self.plot_functions.extend(
            [
                self.plot_overview,
                self.plot_top_cwes,
                self.plot_defects_per_loc,
                self.plot_time_per_loc,
            ]
        )

    def checker_to_category(self, checker: str) -> str:
        """Map a checker name to its category.

        Args:
            checker: The name of the checker.

        Returns:
            The category string for the checker, or "NONE" if not found.

        """
        return self.results[0].checker_to_category(checker)

    def plot_overview(self) -> Figure:
        """Generate an overview plot classifying defects.

        Returns:
            A Matplotlib Figure object containing the plot.

        """
        b = self.benchmark_data
        fig, ax = plt.subplots(1, 1, layout="constrained")
        set_names = ["tp_defects", "fp_defects"]
        X, Y = ["True Positives", "False Positives"], [0, 0]
        COLORS_COUNT = [
            {v: 0 for k, v in self.color_mapping.items()} for _ in range(len(set_names))
        ]
        for result in b.validated_repos:
            for i, name in enumerate(set_names):
                for defect in result[name]:
                    Y[i] += 1
                    color = self.color_mapping[defect.category]
                    COLORS_COUNT[i][color] += 1

                bars = []
                current_height = 0
                for color, height in COLORS_COUNT[i].items():
                    if height > 0:
                        bars.append((X[i], current_height + height, color))
                        current_height += height

                for label, height, color in bars[::-1]:
                    ax.bar(label, height, color=color)

        for i, counts in enumerate(COLORS_COUNT):
            current_height = 0
            for _, height in counts.items():
                invisible_bars = ax.bar(X[i], current_height + height, alpha=0)
                current_height += height
                ax.bar_label(
                    invisible_bars,
                    bbox=dict(facecolor="white", edgecolor="black", pad=1),
                    padding=0,
                )

        ax.set_yscale("log")
        ax.set_title("Classification by checkers category")
        fig.suptitle(
            f"Benchmark against {self.dataset.name} dataset",
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
        """Generate a plot showing the top predicted CWEs.

        Returns:
            A Matplotlib Figure object containing the plot.

        """
        b = self.benchmark_data
        fig, ax = plt.subplots(1, 1, layout="constrained")
        cwe_counter: dict[CWE, dict[str, int]] = {}

        def init_cwe_counter(cwe: CWE) -> None:
            if cwe not in cwe_counter:
                cwe_counter[cwe] = {"tp": 0, "fp": 0, "fn": 0}

        for result in b.validated_repos:
            # True Positives
            for cwe in result["tp_cwes"]:
                init_cwe_counter(cwe)
                cwe_counter[cwe]["tp"] += 1

            # False Positives
            for cwe in result["fp_cwes"]:
                init_cwe_counter(cwe)
                cwe_counter[cwe]["fp"] += 1

            # False Negatives
            for cwe in result["fn_cwes"]:
                init_cwe_counter(cwe)
                cwe_counter[cwe]["fn"] += 1

        X, Y1, Y2, Y3 = [], [], [], []
        # Sort by TP, then FN, then FP
        sorted_cwes = sorted(
            list(cwe_counter.items()),
            key=lambda i: (
                i[1]["tp"],
                i[1]["fn"],
                i[1]["fp"],
            ),
            reverse=True,
        )

        for cwe, v in sorted_cwes[: self.limit]:
            X.append(f"{cwe.name} (ID: {cwe.id})")
            Y1.append(v["tp"])
            Y2.append(v["fp"])
            Y3.append(v["fn"])

        ax.set_xticks(range(len(X)), X, rotation=45, ha="right")
        ax.set_xticklabels(X)
        ax.set_yscale("log")
        width = 0.25
        bars1 = ax.bar(
            [i - width for i in range(len(X))],
            Y1,
            width=width,
            label="True Positives",
            color="green",
        )
        bars2 = ax.bar(
            [i for i in range(len(X))],
            Y2,
            width=width,
            label="False Positives",
            color="orange",
        )
        bars3 = ax.bar(
            [i + width for i in range(len(X))],
            Y3,
            width=width,
            label="False Negatives",
            color="red",
        )
        ax.bar_label(bars1, padding=0)
        ax.bar_label(bars2, padding=0)
        ax.bar_label(bars3, padding=0)
        plt.legend()
        fig.suptitle(f"TOP predicted CWEs on {self.dataset.name}")
        return fig

    def plot_defects_per_loc(self) -> Figure:
        """Generate a scatter plot of defects found versus lines of code.

        Returns:
            A Matplotlib Figure object containing the plot.

        """
        b = self.benchmark_data
        fig, ax = plt.subplots(1, 1, layout="constrained")
        set_names = ["tp_defects", "fp_defects"]
        X, Y = [], []
        for result in b.validated_repos:
            defect_number = sum(len(result[name]) for name in set_names)
            if result["loc"]:
                X.append(result["loc"])
                Y.append(defect_number)

        ax.set_xscale("log")
        ax.scatter(X, Y)

        log_X = np.log10(X)
        coeffs = np.polyfit(log_X, Y, deg=1)
        trend = np.poly1d(coeffs)
        ax.plot(
            X,
            trend(log_X),
            color="red",
            label=f"Trend (Defects = {coeffs[0]:.4f} * log10(LoC) + {coeffs[1]:.4f})",
        )

        ax.set_xlabel("Code lines")
        ax.set_ylabel("Defects")
        ax.set_title(f"Defects against {self.dataset.lang} code lines")
        ax.legend()
        return fig

    def plot_time_per_loc(self) -> Figure:
        """Generate a scatter plot of analysis time versus lines of code.

        Returns:
            A Matplotlib Figure object containing the plot.

        """
        b = self.benchmark_data
        fig, ax = plt.subplots(1, 1, layout="constrained")
        X, Y = [], []

        for result in b.validated_repos:
            if result["loc"]:
                X.append(result["loc"])
                Y.append(result["time"] / 60)

        ax.set_xscale("log")
        ax.scatter(X, Y)

        log_X = np.log10(X)
        coeffs = np.polyfit(log_X, Y, deg=1)
        trend = np.poly1d(coeffs)
        ax.plot(
            X,
            trend(log_X),
            color="red",
            label=f"Trend (Time = {coeffs[0]:.4f} * log10(LoC) + {coeffs[1]:.4f})",
        )

        ax.set_xlabel("Code lines (log scale)")
        ax.set_ylabel("Time taken for analysis (minutes)")
        ax.set_title(f"Analysis time against {self.dataset.lang} code lines")
        ax.legend()
        return fig
