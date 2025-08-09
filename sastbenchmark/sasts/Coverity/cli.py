import os
from pathlib import Path

import click

import sastbenchmark.sasts.Coverity.wrapper.main as Wrapper
from sastbenchmark.sasts.core.cli import CLIFactory
from sastbenchmark.sasts.Coverity.sast import CoveritySAST


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
    os.chdir(Path.cwd())
    Wrapper.main()
