import datasets.BenchmarkJava.stats as BenchmarkJavaStats
import datasets.CVEfixes.stats as CVEfixesStats
import SASTs.Semgrep.analyzer as Analyzer
import SASTs.Semgrep.parser as Parser
from SASTs.Semgrep.constants import *
from utils import *


@click.group(name="semgrep")
def cli():
    """Semgrep Pro Engine"""
    pass

## Analyzer
@cli.command(no_args_is_help=True)
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
    """Quick analyze using Semgrep Pro Engine"""
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

@cli.command()
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
    """Benchmark Semgrep on a dataset"""
    if match:=re.search("CVEfixes_(.*)", dataset):
        lang = match.groups()[0]
        Analyzer.run_CVEfixes(lang, small_first)
    elif match:=re.search("SemgrepTest_(.*)", dataset):
        lang = match.groups()[0]
        Analyzer.run_SemgrepTest(lang, overwrite)
    elif dataset == "BenchmarkJava":
        Analyzer.run_BenchmarkJava(overwrite)

## Parser
@cli.command()
@click.option(
    '--project',
    required=True,
    type=click.Choice(Parser.list_results(project=True), case_sensitive=False),
    show_choices=True,
    help='Name of the project',
)
@click.option(
    '--format',
    required=True,
    type=click.Choice(['json'], case_sensitive=False),
    show_choices=True,
    help='Export analysis results to specific format'
)
def parse(project, format):
    # TODO: save to file
    """Parse Coverity results (aggregate and export)"""
    results = Parser.process_results(os.path.join(RESULT_DIR, project))
    out = Parser.export(results, format)
    click.echo(out)

@cli.command(name="list")
def list_():
    """List existing analysis results"""
    if results:=Parser.list_results(project=True, dataset=True):
        click.echo("Available analysis results:")
        for result in results:
            if result in SUPPORTED_DATASETS:
                click.echo(f"- [Dataset] {result}")
            else:
                click.echo(f"- [Project] {result}")
    else:
        click.echo("No analysis result available")

@cli.command()
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
    """Generate plot for visualization"""
    project_dir = os.path.join(RESULT_DIR, project)
    Parser.plot(project_dir, force=force, show=show, pgf=pgf)

## Stats
@cli.command()
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
    """Display benchmark stats"""
    if match:=re.search("CVEfixes_(.*)", dataset):
        lang = match.groups()[0]
        CVEfixesStats.plot(lang, 'semgrep', force=force, show=show, pgf=pgf)
    elif match:=re.search("SemgrepTest_(.*)", dataset):
        lang = match.groups()[0]
        SemgrepTestStats.plot(lang, 'semgrep', force=force, show=show, pgf=pgf)
    elif dataset == "BenchmarkJava":
        BenchmarkJavaStats.plot('java', 'semgrep', force=force, show=show, pgf=pgf)