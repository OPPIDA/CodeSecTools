import datasets.CVEfixes.stats as CVEfixesStats
import datasets.SemgrepTest.stats as SemgrepTestStats
import datasets.BenchmarkJava.stats as BenchmarkJavaStats
import SASTs.Coverity.analyzer as Analyzer
import SASTs.Coverity.parser as Parser
import SASTs.Coverity.wrapper.main as Wrapper
from SASTs.Coverity.constants import *
from utils import *


@click.group(name="coverity")
def cli():
    """Coverity Static Analysis"""
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
    """Quick analyze using Coverity Buildless capture"""
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
    """Benchmark Coverity on a dataset"""
    if match:=re.search("CVEfixes_(.*)", dataset):
        lang = match.groups()[0]
        Analyzer.run_CVEfixes(lang, small_first)
    elif match:=re.search("SemgrepTest_(.*)", dataset):
        lang = match.groups()[0]
        Analyzer.run_SemgrepTest(lang, overwrite)
    elif dataset == "BenchmarkJava":
        Analyzer.run_BenchmarkJava(overwrite)

@cli.command(name="import")
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
    """Import existing analysis results"""
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
@cli.command()
@click.option(
    '--project',
    required=True,
    type=click.Choice(Parser.list_results() or ['No project available'], case_sensitive=False),
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
    if results:=Parser.list_results():
        click.echo("Available analysis results:")
        for result in results:
            click.echo(f"- {result}")
    else:
        click.echo("No analysis result available")

@cli.command()
@click.option(
    '--project',
    required=True,
    type=click.Choice(Parser.list_results(limit=10) or ['No project available'], case_sensitive=False),
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
    type=click.Choice(Analyzer.list_all_datasets() or ['No dataset available'], case_sensitive=False),
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
        CVEfixesStats.plot(lang, 'coverity', force=force, show=show, pgf=pgf)
    elif match:=re.search("SemgrepTest_(.*)", dataset):
        lang = match.groups()[0]
        SemgrepTestStats.plot(lang, 'coverity', force=force, show=show, pgf=pgf)
    elif dataset == "BenchmarkJava":
        BenchmarkJavaStats.plot('java', 'coverity', force=force, show=show, pgf=pgf)

## Wrapper
@cli.command()
def wrapper():
    """Interact with Coverity commands (Build Capture)"""
    os.chdir(WORKING_DIR)
    Wrapper.main()