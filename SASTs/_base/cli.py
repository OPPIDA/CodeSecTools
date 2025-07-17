import datasets.BenchmarkJava.stats as BenchmarkJavaStats
import datasets.CVEfixes.stats as CVEfixesStats
import datasets.SemgrepTest.stats as SemgrepTestStats
from utils import *


## Analyzer
def add_analyze(cli, LANG, RESULT_DIR, Analyzer, help=""):
    @cli.command(no_args_is_help=True, help=help)
    @click.option(
        '--lang',
        required=True,
        type=click.Choice(LANG.keys(), case_sensitive=False),
        show_choices=True,
        help='Source code langauge (only one at the time)'
    )
    @click.option(
        '--force',
        required=False,
        is_flag=True,
        help='Overwrite existing analysis results for current project'
    )
    def analyze(lang, force):
        result_dir = os.path.join(RESULT_DIR, os.path.basename(WORKING_DIR))
        if os.path.isdir(result_dir):
            click.echo(f"Found existing analysis result at {result_dir}")
            if force:
                shutil.rmtree(result_dir)
                Analyzer.run_analysis(lang, WORKING_DIR, result_dir)
            else:
                click.echo("Use --force to overwrite it")
                sys.exit(1)
        else:
            Analyzer.run_analysis(lang, WORKING_DIR, result_dir)

def add_benchmark(cli, Analyzer, help=""):
    @cli.command(help=help)
    @click.option(
        '--dataset',
        required=True,
        type=click.Choice(Analyzer.list_all_datasets(), case_sensitive=False),
    )
    @click.option(
        '--small-first',
        required=False,
        is_flag=True,
        help='Analyze smaller project of a dataset first (only for CVEfixes)'
    )
    @click.option(
        '--overwrite',
        required=False,
        is_flag=True,
        help='Overwrite existing results (not applicable on CVEfixes)'
    )
    def benchmark(dataset, small_first, overwrite):
        if match:=re.search("CVEfixes_(.*)", dataset):
            lang = match.groups()[0]
            Analyzer.run_CVEfixes(lang, small_first)
        elif match:=re.search("SemgrepTest_(.*)", dataset):
            lang = match.groups()[0]
            Analyzer.run_SemgrepTest(lang, overwrite)
        elif dataset == "BenchmarkJava":
            Analyzer.run_BenchmarkJava(overwrite)

def add_import(cli, RESULT_DIR, Analyzer, help=""):
    @cli.command(name="import", help=help)
    @click.option(
        '--suffix',
        required=False,
        default="",
        type=str,
        help='Add suffix to result directory name'
    )
    @click.option(
        '--force',
        required=False,
        is_flag=True,
        help='Overwrite existing analysis results for current project'
    )
    def import_(suffix, force):
        if suffix: suffix = f"_{suffix}"
        result_dir = os.path.join(RESULT_DIR, os.path.basename(WORKING_DIR) + suffix)
        if os.path.isdir(result_dir):
            click.echo(f"Current project's result already imported at {result_dir}")
            if force:
                shutil.rmtree(result_dir)
                Analyzer.save_results(WORKING_DIR, result_dir)
            else:
                click.echo("Use --force/-f to overwrite it or --suffix to chnage directory name")
                sys.exit(1)
        else:
            Analyzer.save_results(WORKING_DIR, result_dir)

## Parser
def add_list(cli, Parser, SUPPORTED_DATASETS, help=""):
    @cli.command(name="list", help=help)
    def list_():
        if results:=Parser.list_results(project=True, dataset=True):
            click.echo("Available analysis results:")
            for result in results:
                if result in SUPPORTED_DATASETS:
                    click.echo(f"- [Dataset] {result}")
                else:
                    click.echo(f"- [Project] {result}")
        else:
            click.echo("No analysis result available")

def add_plot(cli, Parser, RESULT_DIR, help=""):
    @cli.command(help=help)
    @click.option(
        '--project',
        required=True,
        type=click.Choice(Parser.list_results(project=True, limit=10), case_sensitive=False),
        show_choices=True,
        help='Name of the project',
    )
    @click.option(
        '--force',
        required=False,
        is_flag=True,
        default=False,
        help='Force overwriting existing figures'
    )
    @click.option(
        '--show',
        required=False,
        is_flag=True,
        default=False,
        help='Show figures'
    )
    @click.option(
        '--pgf',
        required=False,
        is_flag=True,
        default=False,
        help='Export figures to pgf format (for LaTex document)'
    )
    def plot(project, force, show, pgf):
        project_dir = os.path.join(RESULT_DIR, project)
        Parser.plot(project_dir, force=force, show=show, pgf=pgf)

## Stats
def add_stats(cli, sast, Analyzer, help=""):
    @cli.command(help=help)
    @click.option(
        '--dataset',
        required=True,
        type=click.Choice(Analyzer.list_all_datasets(), case_sensitive=False),
        show_choices=True,
        help='Name of the dataset',
    )
    @click.option(
        '--force',
        required=False,
        is_flag=True,
        default=False,
        help='Force overwriting existing figures'
    )
    @click.option(
        '--show',
        required=False,
        is_flag=True,
        default=False,
        help='Show figures'
    )
    @click.option(
        '--pgf',
        required=False,
        is_flag=True,
        default=False,
        help='Export figures to pgf format (for LaTex document)'
    )
    def stats(dataset, force, show, pgf):
        if match:=re.search("CVEfixes_(.*)", dataset):
            lang = match.groups()[0]
            CVEfixesStats.plot(lang, sast, force=force, show=show, pgf=pgf)
        elif match:=re.search("SemgrepTest_(.*)", dataset):
            lang = match.groups()[0]
            SemgrepTestStats.plot(lang, sast, force=force, show=show, pgf=pgf)
        elif dataset == "BenchmarkJava":
            BenchmarkJavaStats.plot('java', sast, force=force, show=show, pgf=pgf)