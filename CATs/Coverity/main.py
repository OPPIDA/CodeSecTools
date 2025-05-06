import CATs.Coverity.analyzer as Analyzer
import CATs.Coverity.parser as Parser
import CATs.Coverity.wrapper.main as Wrapper
from CATs.Coverity.constants import *
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
    help='Source code langauge (only one the time)'
)
@click.option(
    '--force',
    required=False,
    is_flag=True,
    help='Overwrite existing analysis results for current project'
)
def analyze(lang, mode, force):
    """Quick analyze using Coverity Buildless capture"""
    result_dir = os.path.join(RESULT_DIR, os.path.basename(WORKING_DIR))
    if os.path.isdir(result_dir):
        print(f"Found existing analysis result at {result_dir}")
        if force:
            shutil.rmtree(result_dir)
            Analyzer.run_single_project_buildless(lang, ".", result_dir)
        else:
            print("Use --force/-f to overwrite it")
            sys.exit(1)
    else:
        Analyzer.run_single_project_buildless(lang, ".", result_dir)

@cli.command()
@click.option(
    '--dataset',
    required=True,
    type=click.Choice(Analyzer.list_all_datasets(), case_sensitive=False),
)
def benchmark(dataset):
    """Benchmark Coverity on a dataset"""
    if match:=re.search("CVEfixes_(.*).csv", dataset):
        lang = match.groups()[0]
        Analyzer.run_CVEfixes(lang)

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
        print(f"Current project's result already imported at {result_dir}")
        if force:
            shutil.rmtree(result_dir)
            Analyzer.save_results(WORKING_DIR, result_dir)
        else:
            print("Use --force/-f to overwrite it or --suffix to chnage directory name")
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
    print(out)

@cli.command()
def list():
    """List existing analysis results"""
    if results:=Parser.list_results():
        print("Available analysis results:")
        for result in results:
            print(f"- {result}")
    else:
        print("No analysis result available")

@cli.command()
@click.option(
    '--project',
    required=True,
    type=click.Choice(Parser.list_results() or ['No project available'], case_sensitive=False),
    show_choices=True,
    help='Name of the project',
)
def plot(project):
    """Generate plot for visualization"""
    results = Parser.process_results(os.path.join(RESULT_DIR, project))
    Parser.plot(results, results['lang'])

## Wrapper
@cli.command()
def wrapper():
    """Interact with Coverity commands"""
    os.chdir(WORKING_DIR)
    Wrapper.main()