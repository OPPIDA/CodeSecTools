import SASTs._base.parser as BaseParser
from SASTs.Semgrep.constants import *
from utils import *


class SemgrepFinding(BaseParser.Defect):
    def __init__(self, defect_data):
        super().__init__(
            file=os.path.basename(defect_data["path"]),
            checker=defect_data["check_id"].split(".")[-1],
            category=defect_data["extra"]["metadata"]["category"],
            cwe_id=int(
                re.search(
                    r"CWE-(\d+)", defect_data["extra"]["metadata"]["cwe"][0]
                ).groups()[0]
            ),
            data=defect_data,
        )

        # Extra
        self.severity = self.data["extra"]["severity"]
        self.lines = self.data["extra"]["lines"]


class SemgrepAnalysisResult(BaseParser.AnalysisResult):
    def __init__(self, result_dir, result_data, analysis_log):
        super().__init__(
            name=os.path.basename(result_dir),
            lang=result_data["interfile_languages_used"],
            files=result_data["paths"]["scanned"],
            defects=[],
            time=result_data["time"]["profiling_times"]["total_time"],
            data=(result_data, analysis_log),
        )

        self.checker_category = {}
        for defect_data in result_data["results"]:
            defect = SemgrepFinding(defect_data)
            self.defects.append(defect)
            self.checker_category[defect.checker] = defect.category

        self.coverage = (
            float(re.search(r"• Parsed lines: ~([\d\.]+)%", analysis_log).groups()[0])
            / 100
        )


def list_results(project=False, dataset=False, limit=None):
    return BaseParser.list_results(
        RESULT_DIR, SUPPORTED_DATASETS, project, dataset, limit
    )


def load_result(result_dir):
    # Analysis log
    analysis_log_path = os.path.join(result_dir, "analysis.log")
    if not os.path.isfile(analysis_log_path):
        raise Exception("Analysis log file not found")
    analysis_log = open(analysis_log_path, "r").read()

    # Analysis outputs
    analysis_output_path = os.path.join(result_dir, "output.json")
    if not os.path.isfile(analysis_output_path):
        raise Exception("Analysis output file not found")
    analysis_output = json.load(open(analysis_output_path, "r"))

    return SemgrepAnalysisResult(result_dir, analysis_output, analysis_log)


def load_dataset_result(dataset, lang):
    """Export the results for comparison with the actual dataset values"""
    if dataset == "BenchmarkJava":
        return load_result(BenchmarkJava_RESULT_DIR)
    else:
        raise Exception("Dataset not supported yet")


## Ploting helpers
def map_colors(labels, checker_category, lang):
    colors = []
    for label in labels:
        # Mapping category to color
        if COLOR_MAPPING.get(label, False):
            colors.append(COLOR_MAPPING[label])

        # Mapping check_id to category color
        if checker_category.get(label) in COLOR_MAPPING.keys():
            colors.append(COLOR_MAPPING[checker_category[label]])

    return colors


## Plot
# TODO: Per CWE
def plot(project_dir, force, show, pgf, limit=10):
    result = load_result(project_dir)
    project_name = result.name
    lang = result.lang
    checker_category = result.checker_category

    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, layout="constrained")
    by_files = result.stats_by_files()
    by_checkers = result.stats_by_checkers()
    by_categories = result.stats_by_categories()

    # Plot by files
    X_files, Y_files = [], []
    sorted_files = sorted(
        list(by_files.items()), key=lambda e: e[1]["count"], reverse=True
    )
    for k, v in sorted_files[:limit]:
        X_files.append(k)
        Y_files.append(v["count"])

        COLORS_COUNT = {v: 0 for k, v in COLOR_MAPPING.items()}

        for checker in v["checkers"]:
            color = map_colors([checker], checker_category, lang)[0]
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
    ax1.set_title(f"Stats by files (limit to {limit})")

    # Plot by checkers
    X_checkers, Y_checkers = [], []
    sorted_checkers = sorted(
        list(by_checkers.items()), key=lambda e: e[1]["count"], reverse=True
    )
    for k, v in sorted_checkers[:limit]:
        X_checkers.append(k)
        Y_checkers.append(v["count"])

    ax2.bar(
        X_checkers, Y_checkers, color=map_colors(X_checkers, checker_category, lang)
    )
    ax2.set_xticks(X_checkers, X_checkers, rotation=45, ha="right")
    ax2.set_title(f"Stats by checkers (limit to {limit})")

    # Plot by categories
    X_categories, Y_categories = [], []
    sorted_categories = sorted(
        list(by_categories.items()), key=lambda e: e[1]["count"], reverse=True
    )
    for k, v in sorted_categories[:limit]:
        X_categories.append(k)
        Y_categories.append(v["count"])

    ax3.bar(
        X_categories,
        Y_categories,
        color=map_colors(X_categories, checker_category, lang),
    )
    ax3.set_xticks(X_categories, X_categories, rotation=45, ha="right")
    ax3.set_title(f"Stats by categories (limit to {limit})")

    # Figure
    fig.suptitle(
        f"Project {project_name}, {len(result.files)} files analyzed, {len(result.defects)} defects raised",
        fontsize=16,
    )
    labels = list(COLOR_MAPPING.keys())
    handles = [
        plt.Rectangle((0, 0), 1, 1, color=COLOR_MAPPING[label]) for label in labels
    ]
    plt.legend(handles, labels)

    # Export
    name = "overview"
    figure_dir = os.path.join(project_dir, "_figures")
    os.makedirs(figure_dir, exist_ok=True)
    figure_path = os.path.join(figure_dir, f"{name}.png")
    if os.path.isfile(figure_path) and not force:
        if not click.confirm(
            f"Found existing figure at {figure_path}, would you like to overwrite?"
        ):
            click.echo(f"{name} not saved")
            return

    fig.set_size_inches(12, 7)
    fig.savefig(figure_path, bbox_inches="tight")
    click.echo(f"Figure {name} saved at {figure_path}")

    if pgf:
        figure_path_pgf = os.path.join(figure_dir, f"{name}.pgf")
        fig.savefig(figure_path_pgf, bbox_inches="tight")
        click.echo(f"Figure {name} exported to pgf")

    if show:
        click.launch(figure_path, wait=False)
