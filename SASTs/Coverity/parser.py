import SASTs._base.parser as BaseParser
from SASTs.Coverity.constants import *
from utils import *


class CoverityDefect(BaseParser.Defect):
    def __init__(self, defect_data):
        super().__init__(
            file = os.path.basename(defect_data['file']),
            checker = defect_data['checker'],
            category = "NONE",
            cwe_id = TYPE_TO_CWE.get(defect_data['type'], None),
            data = defect_data
        )

        self.lang = self.data['lang'].lower()

        if self.checker.startswith('SIGMA'):
            self.category = 'SIGMA'
        elif self.checker.startswith('FB'):
            self.category = 'SPOTBUGS'
        else:
            if self.lang in LANG.keys():
                for set_name, checker_set in LANG[self.lang]['checker_sets'].items():
                    if self.checker in checker_set:
                        self.category = set_name
                        break

        # Extra
        self.function = self.data['function']

class CoverityAnalysisResult(BaseParser.AnalysisResult):
    def __init__(self, result_dir, result_data, config_data, captured_list, defects):
        super().__init__(
            name = os.path.basename(result_dir),
            lang = None,
            files = None,
            defects = defects,
            time = None,
            data = (result_data, config_data, captured_list)
        )

        self.metrics = {}
        for metric in result_data['coverity']['metrics']['metric']:
            self.metrics[metric['name']] = metric['value']

        self.time = int(self.metrics['time'])

        self.files = list(map(lambda line: os.path.basename(line), captured_list.splitlines()))

        file_count = 0
        for lang, pattern in LANG.items():
            include = pattern['include']; exclude = pattern['exclude']
            files = [file for file in self.files if re.search(include, file) and not re.search(exclude, file)]
            if len(files) > file_count:
                file_count = len(files)
                self.lang = lang

        # Extra
        self.config = config_data
        self.analysis_cmd = self.metrics['args']
        self.code_lines = {}
        for key in self.metrics.keys():
            if r:=re.search(r'(.*)-code-lines', key):
                self.code_lines[r.group(1)] = int(self.metrics[key])


def list_results(project=False, dataset=False, limit=None):
    return BaseParser.list_results(RESULT_DIR, SUPPORTED_DATASETS, project, dataset, limit)

def load_result(result_dir):
    # Analysis metrics
    file_path = os.path.join(result_dir, "ANALYSIS.metrics.xml")
    if os.path.isfile(file_path):
        analysis_data = xmltodict.parse(open(file_path, "rb"))
    else:
        raise Exception("Analysis output file not found")

    # Config
    file_path = os.path.join(result_dir, "coverity.yaml")
    if os.path.isfile(file_path):
        config_data = yaml.load(open(file_path, "r"), Loader=yaml.Loader)
    else:
        config_data = None

    # Captured source file list
    captured_list = ""
    for file in glob.glob(os.path.join(result_dir, "capture-files-src-list*")):
        captured_list += open(file, "r").read()

    # Defects
    defects = []
    for file in glob.glob(os.path.join(result_dir, "*errors.xml")):
        f = open(file, "r")
        try:
            errors = xmltodict.parse(f"<root>{f.read()}</root>".encode())['root']['error']
        except TypeError:
            pass

        if isinstance(errors, list):
            for error in errors:
                defects.append(CoverityDefect(error))
        else:
            defects.append(CoverityDefect(errors))

    return CoverityAnalysisResult(result_dir, analysis_data, config_data, captured_list, defects)

def load_dataset_result(dataset, lang):
    """Export the results for comparison with the actual dataset values"""
    if dataset == "CVEfixes":
        defects = []
        for cve_result_dir in glob.glob(os.path.join(CVEfixes_RESULT_DIR, "CVE-*")):
            result = load_result(cve_result_dir)
            if result.lang == lang:
                defects.append(
                    (
                        os.path.basename(cve_result_dir),
                        result.defects,
                        {
                            "time": result.time,
                            "code_lines": result.code_lines,
                        }
                    )
                )
        return defects
    elif dataset == "SemgrepTest":
        return load_result(SemgrepTest_RESULT_DIR)
    elif dataset == "BenchmarkJava":
        return load_result(BenchmarkJava_RESULT_DIR)
    else:
        raise Exception("Dataset not supported")

## Ploting helpers
def map_colors(labels, lang):
    colors = []
    for label in labels:
        # Mapping category to color
        if COLOR_MAPPING.get(label, False):
            colors.append(COLOR_MAPPING[label])
        # Mapping checker to color
        else:
            color = "black"
            # Our own checker sets
            for level, checker_sets in LANG[lang]['checker_sets'].items():
                if label in checker_sets:
                    color = COLOR_MAPPING[level]
                    break

            # Sigma
            if label.startswith("SIGMA"):
                color = COLOR_MAPPING["SIGMA"]
            # SpotBugs
            elif label.startswith("FB"):
                color = COLOR_MAPPING["SPOTBUGS"]

            colors.append(color)

    return colors

## Plot
def plot(project_dir, force, show, pgf, limit=10):
    result = load_result(project_dir)
    project_name = result.name
    lang = result.lang

    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, layout="constrained")
    by_files = result.stats_by_files()
    by_checkers = result.stats_by_checkers()
    by_categories = result.stats_by_categories()

    # Plot by files
    X_files, Y_files = [], []
    sorted_files = sorted(list(by_files.items()), key=lambda e: e[1]['count'], reverse=True)
    for k, v in sorted_files[:limit]:
        X_files.append(k)
        Y_files.append(v['count'])

        COLORS_COUNT = {v: 0 for k,v in COLOR_MAPPING.items()}

        for checker in v['checkers']:
            color = map_colors([checker], lang)[0]
            COLORS_COUNT[color] += 1

        bars = []
        current_height = 0
        for color, height in COLORS_COUNT.items():
            if height > 0:
                bars.append((k, current_height+height, color))
                current_height += height

        for k, height, color in bars[::-1]:
            ax1.bar(k, height, color=color)

    ax1.set_xticks(X_files, X_files, rotation=45, ha="right")
    ax1.set_title(f"Stats by files (limit to {limit})")

    # Plot by checkers
    X_checkers, Y_checkers = [], []
    sorted_checkers = sorted(list(by_checkers.items()), key=lambda e: e[1]['count'], reverse=True)
    for k, v in sorted_checkers[:limit]:
        X_checkers.append(k)
        Y_checkers.append(v['count'])

    ax2.bar(X_checkers, Y_checkers, color=map_colors(X_checkers, lang))
    ax2.set_xticks(X_checkers, X_checkers, rotation=45, ha="right")
    ax2.set_title(f"Stats by checkers (limit to {limit})")

    # Plot by categories
    X_categories, Y_categories = [], []
    sorted_categories = sorted(list(by_categories.items()), key=lambda e: e[1]['count'], reverse=True)
    for k, v in sorted_categories[:limit]:
        X_categories.append(k)
        Y_categories.append(v['count'])

    ax3.bar(X_categories, Y_categories, color=map_colors(X_categories, lang))
    ax3.set_xticks(X_categories, X_categories, rotation=45, ha="right")
    ax3.set_title(f"Stats by categories (limit to {limit})")

    # Figure
    fig.suptitle(f'Project {project_name}, {len(result.files)} files analyzed, {len(result.defects)} defects raised', fontsize=16)
    labels = list(COLOR_MAPPING.keys())
    handles = [plt.Rectangle((0,0),1,1, color=COLOR_MAPPING[label]) for label in labels]
    plt.legend(handles, labels)

    # Export
    name = "overview"
    figure_dir = os.path.join(project_dir, "_figures")
    os.makedirs(figure_dir, exist_ok=True)
    figure_path = os.path.join(figure_dir, f"{name}.png")
    if os.path.isfile(figure_path) and not force:
        if not click.confirm(f"Found existing figure at {figure_path}, would you like to overwrite?"):
            click.echo(f"{name} not saved")
            return

    fig.set_size_inches(12, 7)
    fig.savefig(figure_path, bbox_inches='tight')
    click.echo(f"Figure {name} saved at {figure_path}")

    if pgf:
        figure_path_pgf = os.path.join(figure_dir, f"{name}.pgf")
        fig.savefig(figure_path_pgf, bbox_inches='tight')
        click.echo(f"Figure {name} exported to pgf")

    if show:
        click.launch(figure_path, wait=False)