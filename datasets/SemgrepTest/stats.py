import datasets.SemgrepTest.helper as SemgrepTest
import SASTs.Coverity.constants as CoverityConstants
import SASTs.Coverity.parser as CoverityParser
from utils import *


def parse(lang, sast):
    rules, testcodes = SemgrepTest.load_dataset(lang)
    if sast == "coverity":
        result = CoverityParser.load_dataset_result(SemgrepTest.DATASET_NAME, lang)
        time = True
        code_lines = True
    else:
        raise Exception(f"{sast} is not supported yet")

    file_cwes = {testcode.filename: testcode.cwe_ids for testcode in testcodes}

    testcode_number = len(testcodes)
    defect_number = len(result.defects)

    full_match = []
    false_match = []

    actual_cwes = [cwe_id for testcode in testcodes for cwe_id in testcode.cwe_ids]
    good_cwes = []
    wrong_cwes = []
    for defect in result.defects:
        # Ignore defect without cwe_id
        if not defect.cwe_id:
            continue

        # Found file's CWEs
        if defect.cwe_id in file_cwes[defect.file]:
            full_match.append(defect)
            good_cwes.append(defect.cwe_id)
        # False positive
        else:
            false_match.append(defect)
            wrong_cwes.append(defect.cwe_id)

    unique_correct_number = len(set(defect.file for defect in full_match))

    return full_match, false_match, actual_cwes, good_cwes, wrong_cwes, testcode_number, unique_correct_number

## Dataset specific
def plot_top_cwes():
    fig, ax = plt.subplots(1, 1, layout="constrained")
    cwe_counter = {}
    for cwe_id in actual_cwes:
        if cwe_counter.get(cwe_id, None):
            cwe_counter[cwe_id]['actual'] += 1
        else:
            cwe_counter[cwe_id] = {"good": 0, "wrong": 0, "actual": 1}

    for cwe_id in good_cwes:
        if cwe_counter.get(cwe_id, None):
            cwe_counter[cwe_id]['good'] += 1
        else:
            cwe_counter[cwe_id] = {"good": 1, "wrong": 0, "actual": 0}

    for cwe_id in wrong_cwes:
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
    bars1 = ax.bar([i-width for i in range(len(X))], Y1, width=width, label='Actual (one per test code)', color='blue')
    bars2 = ax.bar([i for i in range(len(X))], Y2, width=width, label='Good prediction (multiple per test code)', color='green')
    bars3 = ax.bar([i+width for i in range(len(X))], Y3, width=width, label='Wrong prediction (multiple per test code)', color='red')
    ax.bar_label(bars1, padding=0)
    ax.bar_label(bars2, padding=0)
    ax.bar_label(bars3, padding=0)
    plt.legend()
    fig.suptitle(f"TOP predicted CWEs")
    return fig

## Coverity specific
def plot_coverity_defects():
    fig, ax = plt.subplots(1, 1, layout="constrained")
    set_names = ['full_match', 'false_match']
    X, Y = ["Correct", "Wrong"], [0, 0]
    COLORS_COUNT = [{v: 0 for k,v in CoverityParser.COLOR_MAPPING.items()} for _ in range(len(set_names))]

    for i, name in enumerate(set_names):
        for defect in eval(name):
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
    fig.suptitle(f'Coverity benchmark against SemgrepTest dataset ({unique_correct_number} unique correct analysis over {testcode_number} test codes)', fontsize=16)
    labels = list(CoverityParser.COLOR_MAPPING.keys())
    handles = [plt.Rectangle((0,0),1,1, color=CoverityParser.COLOR_MAPPING[label]) for label in labels]
    plt.legend(handles, labels)
    return fig

## Main
def plot(lang_, sast_, force, show, pgf):
    global lang, sast, limit, full_match, false_match, actual_cwes, good_cwes, wrong_cwes, testcode_number, unique_correct_number

    limit = 10
    full_match, false_match, actual_cwes, good_cwes, wrong_cwes, testcode_number, unique_correct_number = parse(lang_, sast_)
    lang = lang_
    sast = sast_

    export_dir = None
    figures = [
        (plot_top_cwes(), "top_cwes"),
    ]

    if sast == 'coverity':
        export_dir = CoverityConstants.SemgrepTest_RESULT_DIR
        figures.extend(
            [
                (plot_coverity_defects(), "coverity_defects"),
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