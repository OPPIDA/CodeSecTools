import os
import re
import shutil
import tempfile

import click
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.figure import Figure

from sastbenchmark.data.cwe import CWE
from sastbenchmark.datasets._base.dataset import FileDataset, GitRepoDataset
from sastbenchmark.sasts._base.sast import SAST

## Matplotlib config
matplotlib.rcParams.update(
    {
        "font.family": "serif",
        "font.size": 11,
    }
)


class Graphics:
    def __init__(self, sast: SAST, project_name: str) -> None:
        self.sast = sast
        self.result_dir = os.path.join(sast.result_dir, project_name)
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
            click.echo("pdflatex not found, pgf will not be generated")

    def export(self, force: bool, pgf: bool, show: bool) -> None:
        for plot_function in self.plot_functions:
            fig = plot_function()
            fig_name = plot_function.__name__.replace("plot_", "")
            fig.set_size_inches(12, 7)

            if show:
                with tempfile.NamedTemporaryFile(delete=True) as temp:
                    fig.savefig(f"{temp.name}.png", bbox_inches="tight")
                    click.launch(f"{temp.name}.png", wait=False)

            figure_dir = os.path.join(self.result_dir, "_figures")
            os.makedirs(figure_dir, exist_ok=True)
            figure_path = os.path.join(figure_dir, f"{fig_name}.png")
            if os.path.isfile(figure_path) and not force:
                if not click.confirm(
                    f"Found existing figure at {figure_path}, would you like to overwrite?"
                ):
                    click.echo(f"Figure {fig_name} not saved")
                    continue

            fig.savefig(figure_path, bbox_inches="tight")
            click.echo(f"Figure {fig_name} saved at {figure_path}")

            if pgf and self.has_latex:
                figure_path_pgf = os.path.join(figure_dir, f"{fig_name}.pgf")
                fig.savefig(figure_path_pgf, bbox_inches="tight")
                click.echo(f"Figure {fig_name} exported to pgf")


## Single project
class ProjectGraphics(Graphics):
    def __init__(self, sast: SAST, project_name: str) -> None:
        super().__init__(sast=sast, project_name=project_name)
        self.result = sast.parser.load_from_result_dir(self.result_dir)
        self.plot_functions.extend([self.plot_overview])

    def checker_to_category(self, checker: str) -> str:
        return self.result.checker_to_category(checker)

    def plot_overview(self) -> Figure:
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
    def __init__(self, sast: SAST, dataset: FileDataset) -> None:
        super().__init__(sast=sast, project_name=dataset.full_name)
        self.dataset = dataset
        self.benchmark_data = self.dataset.validate(self.result)
        self.plot_functions.extend([self.plot_top_cwes])

    def plot_top_cwes(self) -> Figure:
        b = self.benchmark_data
        fig, ax = plt.subplots(1, 1, layout="constrained")
        cwe_counter = {}
        for cwe_id in b.cwes_list:
            if cwe_counter.get(cwe_id, None):
                cwe_counter[cwe_id]["actual"] += 1
            else:
                cwe_counter[cwe_id] = {"good": 0, "wrong": 0, "actual": 1}

        for cwe_id in b.correct_cwes:
            if cwe_counter.get(cwe_id, None):
                cwe_counter[cwe_id]["good"] += 1
            else:
                cwe_counter[cwe_id] = {"good": 1, "wrong": 0, "actual": 0}

        for cwe_id in b.incorrect_cwes:
            if cwe_counter.get(cwe_id, None):
                cwe_counter[cwe_id]["wrong"] += 1
            else:
                cwe_counter[cwe_id] = {"good": 0, "wrong": 1, "actual": 0}

        X, Y1, Y2, Y3 = [], [], [], []
        sorted_cwes = sorted(
            list(cwe_counter.items()), key=lambda i: i[1]["actual"], reverse=True
        )
        sorted_cwes = sorted(sorted_cwes, key=lambda i: i[1]["wrong"], reverse=True)
        sorted_cwes = sorted(sorted_cwes, key=lambda i: i[1]["good"], reverse=True)
        for cwe_id, v in sorted_cwes[: self.limit]:
            cwe_name = (
                CWE.get(cwe_id, {}).get("Name", "None") if CWE.get(cwe_id) else "None"
            )
            if r := re.search(r"\('(.*)'\)", cwe_name):
                cwe_name = r.group(1)
            X.append(f"{cwe_name} (ID: {cwe_id})")
            Y1.append(v["actual"])
            Y2.append(v["good"])
            Y3.append(v["wrong"])

        ax.set_xticks(range(len(X)), X, rotation=45, ha="right")
        ax.set_xticklabels(X)
        ax.set_yscale("log")
        width = 0.25
        bars1 = ax.bar(
            [i - width for i in range(len(X))],
            Y1,
            width=width,
            label="Actual (one per test code)",
            color="blue",
        )
        bars2 = ax.bar(
            [i for i in range(len(X))],
            Y2,
            width=width,
            label="Good prediction (multiple per test code)",
            color="green",
        )
        bars3 = ax.bar(
            [i + width for i in range(len(X))],
            Y3,
            width=width,
            label="Wrong prediction (multiple per test code)",
            color="red",
        )
        ax.bar_label(bars1, padding=0)
        ax.bar_label(bars2, padding=0)
        ax.bar_label(bars3, padding=0)
        plt.legend()
        fig.suptitle("TOP predicted CWEs")
        return fig


class GitRepoDatasetGraphics(Graphics):
    def __init__(self, sast: SAST, dataset: GitRepoDataset) -> None:
        super().__init__(sast=sast, project_name=dataset.full_name)
        self.dataset = dataset
        analyzed_repo = {repo.name for repo in dataset.repos} & set(
            os.listdir(self.result_dir)
        )
        repo_paths = (
            os.path.join(self.result_dir, repo_name) for repo_name in analyzed_repo
        )
        self.results = sast.parser.load_from_result_dirs(repo_paths)
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
        return self.results[0].checker_to_category(checker)

    def plot_overview(self) -> Figure:
        b = self.benchmark_data
        fig, ax = plt.subplots(1, 1, layout="constrained")
        set_names = ["correct_defects", "partial_defects", "incorrect_defects"]
        X, Y = ["Correct (file and cwe id)", "Partial (file only)", "False"], [0, 0, 0]
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
            "Benchmark against CVEfixes dataset",
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
        b = self.benchmark_data
        fig, ax = plt.subplots(1, 1, layout="constrained")
        cwe_counter = {}
        for result in b.validated_repos:
            for cwe_id in result["cwes_list"]:
                if cwe_counter.get(cwe_id, None):
                    cwe_counter[cwe_id]["actual"] += 1
                else:
                    cwe_counter[cwe_id] = {"good": 0, "wrong": 0, "actual": 1}

            for cwe_id in result["correct_cwes"]:
                if cwe_counter.get(cwe_id, None):
                    cwe_counter[cwe_id]["good"] += 1
                else:
                    cwe_counter[cwe_id] = {"good": 1, "wrong": 0, "actual": 0}

            for cwe_id in result["incorrect_cwes"]:
                if cwe_counter.get(cwe_id, None):
                    cwe_counter[cwe_id]["wrong"] += 1
                else:
                    cwe_counter[cwe_id] = {"good": 0, "wrong": 1, "actual": 0}

        X, Y1, Y2, Y3 = [], [], [], []
        sorted_cwes = sorted(
            list(cwe_counter.items()), key=lambda i: i[1]["actual"], reverse=True
        )
        sorted_cwes = sorted(sorted_cwes, key=lambda i: i[1]["wrong"], reverse=True)
        sorted_cwes = sorted(sorted_cwes, key=lambda i: i[1]["good"], reverse=True)
        for cwe_id, v in sorted_cwes[: self.limit]:
            cwe_name = (
                CWE.get(cwe_id, {}).get("Name", "None") if CWE.get(cwe_id) else "None"
            )
            if r := re.search(r"\('(.*)'\)", cwe_name):
                cwe_name = r.group(1)
            X.append(f"{cwe_name} (ID: {cwe_id})")
            Y1.append(v["actual"])
            Y2.append(v["good"])
            Y3.append(v["wrong"])

        ax.set_xticks(range(len(X)), X, rotation=45, ha="right")
        ax.set_xticklabels(X)
        ax.set_yscale("log")
        width = 0.25
        bars1 = ax.bar(
            [i - width for i in range(len(X))],
            Y1,
            width=width,
            label="Actual (one per CVE)",
            color="blue",
        )
        bars2 = ax.bar(
            [i for i in range(len(X))],
            Y2,
            width=width,
            label="Good prediction (multiple per CVE)",
            color="green",
        )
        bars3 = ax.bar(
            [i + width for i in range(len(X))],
            Y3,
            width=width,
            label="Wrong prediction (multiple per CVE)",
            color="red",
        )
        ax.bar_label(bars1, padding=0)
        ax.bar_label(bars2, padding=0)
        ax.bar_label(bars3, padding=0)
        plt.legend()
        fig.suptitle("TOP predicted CWEs")
        return fig

    def plot_defects_per_loc(self) -> Figure:
        b = self.benchmark_data
        fig, ax = plt.subplots(1, 1, layout="constrained")
        set_names = ["correct_defects", "partial_defects", "incorrect_defects"]
        X, Y = [], []
        for result in b.validated_repos:
            defect_number = sum(len(result[name]) for name in set_names)
            if result["loc"] and result["time"] > 180:
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
        b = self.benchmark_data
        fig, ax = plt.subplots(1, 1, layout="constrained")
        X, Y = [], []

        for result in b.validated_repos:
            if result["loc"] and result["time"] > 180:
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
