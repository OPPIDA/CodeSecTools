from SASTs.Coverity.constants import *
from utils import *


def save_results(project_dir, result_dir):
    # Output directory
    os.makedirs(result_dir, exist_ok=True)

    # Save config file if exists
    config_path = os.path.join(project_dir, "coverity.yaml")
    if os.path.isfile(config_path):
        shutil.copy2(config_path, os.path.join(result_dir, "coverity.yaml"))

    # Save captured source files list
    capture_path = os.path.join(project_dir, "idir", "coverity-cli")
    for file in os.listdir(capture_path):
        if file.startswith("capture-files-src-list"):
            full_src_path = os.path.join(capture_path, file)
            full_dst_path = os.path.join(result_dir, file)
            shutil.copy2(full_src_path, full_dst_path)

    # Save analysis result
    output_path = os.path.join(project_dir, "idir", "output")

    for filename in os.listdir(output_path):
        if filename.lower().endswith(".xml"):
            full_src_path = os.path.join(output_path, filename)
            full_dst_path = os.path.join(result_dir, filename)
            shutil.copy2(full_src_path, full_dst_path)

    click.echo(f"Results are saved in {result_dir}")

def run_single_project_buildless(lang, project_dir, result_dir):
    # Coverity buildless capture
    start = time.time()
    _ = run_command(f"coverity capture --disable-build-command-inference --language {lang}", project_dir)

    # Support Java only
    # TODO: C/C++, support config flag -co
    _ = run_command("cov-analyze --dir idir --all-security --enable-callgraph-metrics", project_dir)
    end = time.time()
    click.echo(f"Time taken (capture + analysis): {timedelta(seconds=end-start)}")

    save_results(project_dir, result_dir)

## Datasets
import datasets.CVEfixes.helper as CVEfixes
import datasets.SemgrepTest.helper as SemgrepTest
import datasets.BenchmarkJava.helper as BenchmarkJava


# TODO: max repo size
def run_CVEfixes(lang, small_first=False):
    cves = CVEfixes.load_dataset(lang=lang)
    os.makedirs(CVEfixes_RESULT_DIR, exist_ok=True)

    if small_first:
        cves = sorted(cves, key=lambda cve: cve.repo_size)

    for cve in cves:
        click.echo("=================================")
        click.echo(cve)

        result_path = os.path.join(CVEfixes_RESULT_DIR, cve.cve_id)
        if os.path.isdir(result_path):
            if os.listdir(result_path):
                click.echo("Results already exist, skiping...")
                continue

        click.echo(f"Repo size: {humanize.naturalsize(cve.repo_size)}")

        if cve.repo_size > 1 * 1e9:
            click.echo("Repo size exceeding 1 GB, skiping...")
            continue

        # Create temporary directory for the project
        temp_dir = tempfile.TemporaryDirectory()
        repo_path = temp_dir.name

        # Clone and checkout to the vulnerable commit
        try:
            repo = git.Repo.clone_from(cve.repo_url, repo_path)
            repo.git.checkout(cve.parents[0])
        except git.exc.GitCommandError as e:
            click.echo(e)
            click.echo("Skipping")
            continue

        # Run analysis
        run_single_project_buildless(lang, repo_path, result_path)

        # Clear temporary directory
        temp_dir.cleanup()

def run_SemgrepTest(lang, overwrite=False):
    _, testcodes = SemgrepTest.load_dataset(lang)

    result_path = SemgrepTest_RESULT_DIR
    os.makedirs(result_path, exist_ok=True)

    if os.path.isdir(result_path):
        if os.listdir(result_path) and not overwrite:
            click.echo("Results already exist, please use --overwrite to delete old results")
            return

    # Create temporary directory for the project
    temp_dir = tempfile.TemporaryDirectory()
    temp_path = temp_dir.name

    # Copy test files into the temporary directory
    for testcode in testcodes:
        testcode.save(temp_path)

    # Run analysis
    run_single_project_buildless(lang, temp_path, result_path)

    # Clear temporary directory
    temp_dir.cleanup()

def run_BenchmarkJava(overwrite=False):
    testcodes = BenchmarkJava.load_dataset()

    result_path = BenchmarkJava_RESULT_DIR
    os.makedirs(result_path, exist_ok=True)

    if os.path.isdir(result_path):
        if os.listdir(result_path) and not overwrite:
            click.echo("Results already exist, please use --overwrite to delete old results")
            return

    # Create temporary directory for the project
    temp_dir = tempfile.TemporaryDirectory()
    temp_path = temp_dir.name

    # Copy test files into the temporary directory
    for testcode in testcodes:
        testcode.save(temp_path)

    # Run analysis
    run_single_project_buildless("java", temp_path, result_path)

    # Clear temporary directory
    temp_dir.cleanup()


def list_all_datasets():
    all_datasets = []
    all_datasets.extend(CVEfixes.list_dataset())
    all_datasets.extend(SemgrepTest.list_dataset())
    all_datasets.extend(BenchmarkJava.list_dataset())
    return all_datasets