import os

import click

import sasts.Coverity.wrapper.main as Wrapper
from sasts._base.cli import CLIFactory
from sasts.Coverity.sast import CoveritySAST
from utils import WORKING_DIR


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


## Wrapper
@CoverityCLI.command()
def wrapper() -> None:
    """Interact with Coverity commands (Build Capture)"""
    os.chdir(WORKING_DIR)
    Wrapper.main()
