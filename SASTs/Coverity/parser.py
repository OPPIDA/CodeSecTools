import SASTs.Coverity.parser as Parser
from SASTs.Coverity.constants import *
from utils import *


# TODO: Parent class: Defect
class CoverityDefect:
    def __init__(self, xml_dict):
        self.xml_dict = xml_dict
        self.lang = xml_dict['lang'].lower()
        self.checker = xml_dict['checker']

        self.category = "NONE"
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

        if self.category == "None":
            click.echo(self.checker)

        self.type = xml_dict['type']
        self.cwe_id = TYPE_TO_CWE.get(self.type, None)
        self.file = os.path.basename(xml_dict['file'])
        self.function = xml_dict['function']

    def __repr__(self):
        return f"""{self.__class__.__name__}(
    file: \t{self.file}
    function: \t{self.function}
    type: \t{self.type}
    checker: \t{self.checker}
    category: \t{self.category}
    cwe_id: \t{self.cwe_id}
)"""

    @classmethod
    def load(cls, xml_dict):
        return cls(xml_dict)

class CoverityAnalysisStats:
    def __init__(self, xml_dict):
        self.xml_dict = xml_dict
        self.metrics = {}
        for metric in xml_dict['coverity']['metrics']['metric']:
            self.metrics[metric['name']] = metric['value']

        self.time = int(self.metrics['time'])
        self.analysis_cmd = self.metrics['args']

        self.defect_count = self.metrics['total-new-defect-count']
        self.defect = None # Mandatory

        self.code_lines = {}
        for key in self.metrics.keys():
            if r:=re.search(r'(.*)-code-lines', key):
                self.code_lines[r.group(1)] = int(self.metrics[key])

        self.TSF = None # Optional

    def __repr__(self):
        # TODO
        return f"{self.__class__.__name__}()"

    @classmethod
    def load(cls, xml_dict):
        return cls(xml_dict)

    def load_defects(self, defects):
        self.defects = defects

    def load_TSF(self, TSF):
        self.TSF = TSF

    def stats_by_checkers(self):
        stats = {}
        for defect in self.defects:
            if defect.checker not in stats.keys():
                stats[defect.checker] = {'count': 1, 'files': {defect.file}}
            else:
                stats[defect.checker]['files'].add(defect.file)
                stats[defect.checker]['count'] = len(stats[defect.checker]['files'])

        return stats

    def stats_by_categories(self):
        stats = {}
        for defect in self.defects:
            if defect.category not in stats.keys():
                stats[defect.category] = {'count': 1, 'checkers': [defect.checker], 'unique': 1}
            else:
                stats[defect.category]['checkers'].append(defect.checker)
                stats[defect.category]['count'] = len(stats[defect.category]['checkers'])
                stats[defect.category]['unique'] = len(set(stats[defect.category]['checkers']))

        return stats

    def stats_by_files(self):
        stats = {}
        for defect in self.defects:
            if self.TSF:
                if defect.file not in self.TSF:
                    continue
            if defect.file not in stats.keys():
                stats[defect.file] = {'count': 1, 'checkers': {defect.checker}}
            else:
                stats[defect.file]['checkers'].add(defect.checker)
                stats[defect.file]['count'] = len(stats[defect.file]['checkers'])

        return stats

    def stats_by_cwes(self):
        stats = {}
        for defect in self.defects:
            if defect.cwe_id not in stats.keys():
                stats[defect.cwe_id] = {'count': 1, 'files': {defect.file}}
            else:
                stats[defect.cwe_id]['files'].add(defect.file)
                stats[defect.cwe_id]['count'] = len(stats[defect.cwe]['files'])

        return stats

class CapturedSrcFiles:
    def __init__(self, f):
        self.file_list = map(lambda line: os.path.basename(line), f.read().splitlines())

        self.main_lang, temp_counter = None, 0
        self.files_by_lang = {}
        for lang, pattern in LANG.items():
            include = pattern['include']
            exclude = pattern['exclude']

            files = []
            for file in self.file_list:
                if re.search(include, file) and not re.search(exclude, file):
                    files.append(file)

            self.files_by_lang[lang] = (len(files), files)

            if len(files) > temp_counter:
                temp_counter = len(files)
                self.main_lang = lang

def list_results(limit=None):
    result_dirs = []
    if os.path.isdir(RESULT_DIR):
        for child in os.listdir(RESULT_DIR):
            child_path = os.path.join(RESULT_DIR, child)
            if os.path.isdir(child_path):
                # Exclude dataset results
                if not child in DATASETS:
                    result_dirs.append(child)

    result_dirs = sorted(result_dirs)
    return result_dirs

def process_results(result_dir):
    results = {}

    # Config
    file_path = os.path.join(result_dir, "coverity.yaml")
    if os.path.isfile(file_path):
        f = open(file_path, "r")
        results['config'] = yaml.load(f, Loader=yaml.Loader)

    # Analysis metrics
    file_path = os.path.join(result_dir, "ANALYSIS.metrics.xml")
    if os.path.isfile(file_path):
        f = open(file_path, "rb")
        results['stats'] = CoverityAnalysisStats(xmltodict.parse(f))

    # Captured source file list
    for file in glob.glob(os.path.join(result_dir, "capture-files-src-list*")):
        f = open(file, "r")
        results['captured'] = CapturedSrcFiles(f)
        results['lang'] = results['captured'].main_lang

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
                defects.append(CoverityDefect.load(error))
        else:
            defects.append(CoverityDefect.load(errors))

    results['stats'].load_defects(defects)

    return results

def export(results, format):
    data = {
        'lang': results['lang'],
        'config' : results.get('config', {}),
        'files': results['captured'].files_by_lang,
        'defects': {
            'count': results['stats'].defect_count,
            'per_checker': results['stats'].stats_by_checkers(),
            'per_file': results['stats'].stats_by_files(),
            'per_category': results['stats'].stats_by_categories(),
            'per_cwe': results['stats'].stats_by_cwes(),
        }
    }

    if format == "json":
        return json.dumps(data, default=list, indent=2)

def export_for(dataset, lang):
    """Export the results for comparison with the actual dataset values"""
    if dataset == "CVEfixes":
        defects = []
        for cve_result_dir in glob.glob(os.path.join(CVEfixes_RESULT_DIR, "CVE-*")):
            results = process_results(cve_result_dir)
            if results['lang'] == lang:
                defects.append(
                    (
                        os.path.basename(cve_result_dir),
                        results['stats'].defects,
                        {
                            "time": results['stats'].time,
                            "code_lines": results['stats'].code_lines,
                        }
                    )
                )
    elif dataset == "SemgrepTest":
        results = process_results(SemgrepTest_RESULT_DIR)
        return results['stats'].defects
    elif dataset == "BenchmarkJava":
        results = process_results(BenchmarkJava_RESULT_DIR)
        return results['stats'].defects
    else:
        raise Exception("Dataset not supported")

    return defects

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
# TODO: Per CWE
def plot(project_dir, force, show, pgf, limit=10):
    results = Parser.process_results(project_dir)
    project_name = os.path.basename(project_dir)
    lang = results['lang']

    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, layout="constrained")
    files = results['stats'].stats_by_files()
    checkers = results['stats'].stats_by_checkers()
    categories = results['stats'].stats_by_categories()

    # Plot for files
    X_files, Y_files = [], []
    sorted_files = sorted(list(files.items()), key=lambda e: e[1]['count'], reverse=True)
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

    # Plot for checkers
    X_checkers, Y_checkers = [], []
    sorted_checkers = sorted(list(checkers.items()), key=lambda e: e[1]['count'], reverse=True)
    for k, v in sorted_checkers[:limit]:
        X_checkers.append(k)
        Y_checkers.append(v['count'])

    ax2.bar(X_checkers, Y_checkers, color=map_colors(X_checkers, lang))
    ax2.set_xticks(X_checkers, X_checkers, rotation=45, ha="right")
    ax2.set_title(f"Stats by checkers (limit to {limit})")

    # Plot for categories
    X_categories, Y_categories = [], []
    sorted_categories = sorted(list(categories.items()), key=lambda e: e[1]['count'], reverse=True)
    for k, v in sorted_categories[:limit]:
        X_categories.append(k)
        Y_categories.append(v['count'])

    ax3.bar(X_categories, Y_categories, color=map_colors(X_categories, lang))
    ax3.set_xticks(X_categories, X_categories, rotation=45, ha="right")
    ax3.set_title(f"Stats by categories (limit to {limit})")

    # Figure
    fig.suptitle(f'Project {project_name} ({len(files)} files analyzed, {len(checkers)} checkers triggered)', fontsize=16)
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