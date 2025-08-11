import click

from codesectools.sasts.core.cli import CLIFactory
from codesectools.sasts.Coverity.sast import CoveritySAST


@click.group(name="coverity")
def CoverityCLI() -> None:
    """Coverity Static Analysis"""
    pass


CLIFactory(
    CoverityCLI,
    CoveritySAST(),
    help_messages={
        "analyze": """Quick analyze using Coverity Buildless capture""",
        "benchmark": """Benchmark Coverity on a dataset""",
        "list": """List existing analysis results""",
        "plot": """Generate plot for visualization""",
    },
)
