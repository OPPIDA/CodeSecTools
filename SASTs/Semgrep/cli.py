import SASTs._base.cli as CLITemplate
import SASTs.Semgrep.analyzer as Analyzer
import SASTs.Semgrep.parser as Parser
from SASTs.Semgrep.constants import *
from utils import *


@click.group(name="semgrep")
def cli():
    """Semgrep Pro Engine"""
    pass


## Analyzer
CLITemplate.add_analyze(
    cli, LANG, RESULT_DIR, Analyzer, help="""Quick analyze using Semgrep Pro Engine"""
)

CLITemplate.add_benchmark(cli, Analyzer, help="""Benchmark Semgrep on a dataset""")

## Parser
CLITemplate.add_list(
    cli, Parser, SUPPORTED_DATASETS, help="""List existing analysis results"""
)

CLITemplate.add_plot(
    cli, Parser, RESULT_DIR, help="""Generate plot for visualization"""
)

## Stats
CLITemplate.add_stats(cli, "semgrep", Analyzer, help="""Display benchmark stats""")
