import datasets.CVEfixes.helper as CVEfixes
import SASTs.Coverity.constants as CoverityConstants
import SASTs.Coverity.parser as CoverityParser
from utils import *


def parse(lang, sast):
    # Extra metrics
    time = None
    code_lines = None

    cves = CVEfixes.load_dataset(lang)
    if sast == "coverity":
        results = CoverityParser.load_dataset_result(CVEfixes.DATASET_NAME, lang)
        time = True
        code_lines = True
    else:
        raise Exception(f"{sast} is not supported yet")

    final_results = {}
    final_results['sast'] = sast
    final_results['lang'] = lang
    final_results['project_number'] = len(results)
    final_results['defect_number'] = sum(len(r[1]) for r in results)
    final_results['matches'] = []

    actual = []
    predicted = []
    extras = []
    for cve_dir, defects, extra in results:
        actual.append(cves[cves.index(cve_dir)])
        predicted.append(defects)
        extras.append(extra)

    for cve, defects, extra in zip(actual, predicted, extras):
        actual_files = cve.filenames
        actual_cwes = list(map(lambda s: int(s.split('-')[1]), cve.cwe_ids))

        full_match = []
        partial_match = []
        false_match = []

        good_cwes = []
        wrong_cwes = []
        for defect in defects:
            # Ignore defect without cwe_id
            if not defect.cwe_id:
                continue

            # Found vulnerable file and the right CWE
            if defect.file in actual_files and defect.cwe_id in actual_cwes:
                full_match.append(defect)
                good_cwes.append(defect.cwe_id)
            # Found vulnerable file but not for the right reason
            elif defect.file in actual_files and defect.file:
                partial_match.append(defect)
                wrong_cwes.append(defect.cwe_id)
            # False positive
            else:
                false_match.append(defect)
                wrong_cwes.append(defect.cwe_id)

        result = {
            "cve_id": cve.cve_id,
            "full_match": full_match,
            "partial_match": partial_match,
            "false_match": false_match,
            "actual_cwes": actual_cwes,
            "good_cwes": good_cwes,
            "wrong_cwes": wrong_cwes,
        }

        # Extra
        result['time'] = extra['time'] if time else None
        result['code_lines'] = extra['code_lines'] if code_lines else None

        final_results['matches'].append(result)

    return final_results

## Datset specific
def plot_overview():
    fig, ax = plt.subplots(1, 1, layout="constrained")
    X, Y1, Y2 = ["File and CWE id", "CWE id only", "False positive"], [0, 0, 0], [0, 0, 0]
    for match in matches:
        Y1[0] += len(match['full_match'])
        Y1[1] += len(match['partial_match'])
        Y1[2] += len(match['false_match'])
        Y2[0] += len({m.file for m in match['full_match']})
        Y2[1] += len({m.file for m in match['partial_match']})
        Y2[2] += len({m.file for m in match['false_match']})

    bars1 = ax.bar(X, Y1, label='All matches (multiple match for a same file)', color='pink')
    bars2 = ax.bar(X, Y2, label='Unique matches (at most one match for a same file)', color='purple')
    ax.bar_label(bars1, padding=0)
    ax.bar_label(bars2, padding=0)
    ax.legend(title="Match Type")
    ax.set_yscale('log')
    fig.suptitle(f"SAST Result Validation Against Actual Dataset (Total defects: {defect_number})")
    return fig

def plot_top_cwes():
    fig, ax = plt.subplots(1, 1, layout="constrained")
    cwe_counter = {}
    for match in matches:
        for cwe_id in match["actual_cwes"]:
            if cwe_counter.get(cwe_id, None):
                cwe_counter[cwe_id]['actual'] += 1
            else:
                cwe_counter[cwe_id] = {"good": 0, "wrong": 0, "actual": 1}

        for cwe_id in match["good_cwes"]:
            if cwe_counter.get(cwe_id, None):
                cwe_counter[cwe_id]['good'] += 1
            else:
                cwe_counter[cwe_id] = {"good": 1, "wrong": 0, "actual": 0}

        for cwe_id in match["wrong_cwes"]:
            if cwe_counter.get(cwe_id, None):
                cwe_counter[cwe_id]['wrong'] += 1
            else:
                cwe_counter[cwe_id] = {"good": 0, "wrong": 1, "actual": 0}

    X, Y1, Y2, Y3 = [], [], [], []
    sorted_cwes = sorted(list(cwe_counter.items()), key=lambda i: i[1]["actual"], reverse=True)
    sorted_cwes = sorted(sorted_cwes, key=lambda i: i[1]["wrong"], reverse=True)
    sorted_cwes = sorted(sorted_cwes, key=lambda i: i[1]["good"], reverse=True)
    for cwe_id, v in sorted_cwes[:limit]:
        cwe_name = CWE.get(cwe_id).get('Name', 'None') if CWE.get(cwe_id) else 'None'
        if r:=re.search(r"\('(.*)'\)", cwe_name):
            cwe_name = r.group(1)
        X.append(f"{cwe_name} (ID: {cwe_id})")
        Y1.append(v["actual"])
        Y2.append(v["good"])
        Y3.append(v["wrong"])

    ax.set_xticks(range(len(X)), X, rotation=45, ha="right")
    ax.set_xticklabels(X)
    ax.set_yscale('log')
    width = 0.25
    bars1 = ax.bar([i-width for i in range(len(X))], Y1, width=width, label='Actual (one per CVE)', color='blue')
    bars2 = ax.bar([i for i in range(len(X))], Y2, width=width, label='Good prediction (multiple per CVE)', color='green')
    bars3 = ax.bar([i+width for i in range(len(X))], Y3, width=width, label='Wrong prediction (multiple per CVE)', color='red')
    ax.bar_label(bars1, padding=0)
    ax.bar_label(bars2, padding=0)
    ax.bar_label(bars3, padding=0)
    plt.legend()
    fig.suptitle(f"TOP predicted CWEs")
    return fig

## Coverity specific
def plot_coverity_classification():
    fig, ax = plt.subplots(1, 1, layout="constrained")
    set_names = ['full_match', 'partial_match', 'false_match']
    X, Y = ["Correct (file and cwe id)", "Partial (file only)", "False"], [0, 0, 0]
    COLORS_COUNT = [{v: 0 for k,v in CoverityParser.COLOR_MAPPING.items()} for _ in range(len(set_names))]
    for match in matches:
        for i, name in enumerate(set_names):
            for defect in match[name]:
                Y[i] += 1
                color = CoverityParser.map_colors([defect.checker], lang)[0]
                COLORS_COUNT[i][color] += 1

            bars = []
            current_height = 0
            for color, height in COLORS_COUNT[i].items():
                if height > 0:
                    bars.append((X[i], current_height+height, color))
                    current_height += height

            for label, height, color in bars[::-1]:
                bar = ax.bar(label, height, color=color)

    for i, counts in enumerate(COLORS_COUNT):
        current_height = 0
        for color, height in counts.items():
            invisible_bars = ax.bar(X[i], current_height+height, alpha=0)
            current_height += height
            ax.bar_label(invisible_bars, bbox=dict(facecolor='white', edgecolor='black', pad=1), padding=0)

    ax.set_yscale('log')
    ax.set_title(f"Classification by Coverity checkers category")
    fig.suptitle(f'Coverity benchmark against CVEfixes dataset ({cve_found_number} CVE found over {project_number} project)', fontsize=16)
    labels = list(CoverityParser.COLOR_MAPPING.keys())
    handles = [plt.Rectangle((0,0),1,1, color=CoverityParser.COLOR_MAPPING[label]) for label in labels]
    plt.legend(handles, labels)
    return fig

def plot_coverity_defects():
    fig, ax = plt.subplots(1, 1, layout="constrained")
    set_names = ['full_match', 'partial_match', 'false_match']
    X, Y = [], []
    for match in matches:
        defect_number = sum(len(match[name]) for name in set_names)
        if match['code_lines'].get(lang) and match['time'] > 180:
            X.append(match['code_lines'].get(lang))
            Y.append(defect_number)

    ax.set_xscale('log')
    ax.scatter(X, Y)

    log_X = np.log10(X)
    coeffs = np.polyfit(log_X, Y, deg=1)
    trend = np.poly1d(coeffs)
    ax.plot(X, trend(log_X), color='red', label=f'Trend (Defects = {coeffs[0]:.4f} * log10(LoC) + {coeffs[1]:.4f})')

    ax.set_xlabel('Code lines')
    ax.set_ylabel('Defects')
    ax.set_title(f'Defects against {lang} code lines')
    ax.legend()
    return fig

def plot_coverity_time():
    fig, ax = plt.subplots(1, 1, layout="constrained")
    X, Y = [], []

    for match in matches:
        if match['code_lines'].get(lang) and match['time'] > 180:
            X.append(match['code_lines'].get(lang))
            Y.append(match['time']/60)

    ax.set_xscale('log')
    ax.scatter(X, Y)

    log_X = np.log10(X)
    coeffs = np.polyfit(log_X, Y, deg=1)
    trend = np.poly1d(coeffs)
    ax.plot(X, trend(log_X), color='red', label=f'Trend (Time = {coeffs[0]:.4f} * log10(LoC) + {coeffs[1]:.4f})')

    ax.set_xlabel('Code lines (log scale)')
    ax.set_ylabel('Time taken for analysis (minutes)')
    ax.set_title(f'Analysis time against {lang} code lines')
    ax.legend()
    return fig

## Main
def plot(lang_, sast_, force, show, pgf):
    global lang, sast, limit, results, project_number, defect_number, matches, cve_found_number

    limit = 10
    results = parse(lang_, sast_)
    lang = results["lang"]
    sast = results["sast"]
    project_number = results['project_number']
    defect_number = results['defect_number']
    matches = results['matches']
    cve_found_number = len([match for match in matches if len(match['full_match']) > 0])

    export_dir = None
    figures = [
        (plot_overview(), "overview"),
        (plot_top_cwes(), "top_cwes"),
    ]

    if sast == 'coverity':
        export_dir = CoverityConstants.CVEfixes_RESULT_DIR
        figures.extend(
            [
                (plot_coverity_classification(), "coverity_classification"),
                (plot_coverity_defects(), "coverity_defects"),
                (plot_coverity_time(), "coverity_time"),
            ]
        )

    if export_dir:
        figure_dir = os.path.join(export_dir, "_figures")
        os.makedirs(figure_dir, exist_ok=True)
        for fig, name in figures:
            figure_path = os.path.join(figure_dir, f"{name}.png")
            if os.path.isfile(figure_path) and not force:
                if not click.confirm(f"Found existing figure at {figure_path}, would you like to overwrite?"):
                    click.echo(f"{name} not saved")
                    continue

            fig.set_size_inches(12, 7)
            fig.savefig(figure_path, bbox_inches='tight')
            click.echo(f"Figure {name} saved at {figure_path}")

            if pgf:
                figure_path_pgf = os.path.join(figure_dir, f"{name}.pgf")
                fig.savefig(figure_path_pgf, bbox_inches='tight')
                click.echo(f"Figure {name} exported to pgf")

            if show:
                click.launch(figure_path, wait=False)