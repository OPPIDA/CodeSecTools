#!/usr/bin/env python3
import SASTs.Coverity.main as Coverity
from utils import *


@click.group()
@click.option(
    '--debug',
    required=False,
    is_flag=True,
    help='Show all debug messages'
)
def cli(debug):
    """SAST Benchmark"""
    if debug:
        os.environ["DEBUG"] = "1"

cli.add_command(Coverity.cli)

if __name__ == '__main__':
    cli()