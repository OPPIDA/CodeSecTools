from SASTs.Semgrep.constants import *
from utils import *


def save_results(project_dir, result_dir, analysis_log):
    # Output directory
    os.makedirs(result_dir, exist_ok=True)

    # Save analysis log for metrics
    with open(os.path.join(result_dir, "analysis.log"), "w") as f:
        f.write(analysis_log)

    # Save analysis result
    output_path = os.path.join(project_dir, "output.json")
    if os.path.isfile(output_path):
        shutil.copy2(output_path, os.path.join(result_dir, "output.json"))
    else:
        raise Exception("Semgrep analysis result not found")

    click.echo(f"Results are saved in {result_dir}")


def run_analysis(lang, project_dir, result_dir):
    # Semgrep Pro Engine scan
    start = time.time()
    analysis_log = run_command(
        f"semgrep scan --config=p/{lang} --pro --metrics=off --json-output=output.json",
        project_dir,
    )
    end = time.time()
    click.echo(f"Time taken: {timedelta(seconds=end-start)}")

    save_results(project_dir, result_dir, analysis_log)


## Datasets
import datasets.BenchmarkJava.helper as BenchmarkJava


def run_BenchmarkJava(overwrite=False):
    testcodes = BenchmarkJava.load_dataset()

    result_path = BenchmarkJava_RESULT_DIR
    os.makedirs(result_path, exist_ok=True)

    if os.path.isdir(result_path):
        if os.listdir(result_path) and not overwrite:
            click.echo(
                "Results already exist, please use --overwrite to delete old results"
            )
            return

    # Create temporary directory for the project
    temp_dir = tempfile.TemporaryDirectory()
    temp_path = temp_dir.name

    # Copy test files into the temporary directory
    for testcode in testcodes:
        testcode.save(temp_path)

    # Run analysis
    run_analysis("java", temp_path, result_path)

    # Clear temporary directory
    temp_dir.cleanup()


def list_all_datasets():
    all_datasets = []
    all_datasets.extend(BenchmarkJava.list_dataset())
    return all_datasets
