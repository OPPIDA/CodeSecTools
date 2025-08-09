import click

from sastbenchmark.sasts._core.cli import CLIFactory
from sastbenchmark.sasts.Semgrep.sast import SemgrepSAST


@click.group(name="semgrep")
def SemgrepCLI() -> None:
    """Semgrep Pro Engine"""
    pass


CLIFactory(
    SemgrepCLI,
    SemgrepSAST(),
    help_messages={
        "analyze": """Quick analyze using Semgrep Pro Engine""",
        "benchmark": """Benchmark Semgrep on a dataset""",
        "list": """List existing analysis results""",
        "plot": """Generate plot for visualization""",
    },
)
