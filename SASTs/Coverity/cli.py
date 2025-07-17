import SASTs._base.cli as CLITemplate
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
CLITemplate.add_analyze(cli, LANG, RESULT_DIR, Analyzer,
    help = """Quick analyze using Coverity Buildless capture"""
)

CLITemplate.add_benchmark(cli, Analyzer,
    help = """Benchmark Coverity on a dataset"""
)

CLITemplate.add_import(cli, RESULT_DIR, Analyzer,
    help = """Import existing Coverity analysis results"""
)

## Parser
CLITemplate.add_list(cli, Parser, SUPPORTED_DATASETS,
    help = """List existing analysis results"""
)

CLITemplate.add_plot(cli, Parser, RESULT_DIR,
    help="""Generate plot for visualization"""
)

## Stats
CLITemplate.add_stats(cli, "coverity", Analyzer,
    help = """Display benchmark stats"""
)

## Wrapper
@cli.command()
def wrapper():
    """Interact with Coverity commands (Build Capture)"""
    os.chdir(WORKING_DIR)
    Wrapper.main()