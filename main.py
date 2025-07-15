import SASTs.Coverity.main as Coverity
from utils import *

@click.group()
@click.option(
    '--silent',
    required=False,
    is_flag=True,
    help=''
)
def cli(silent):
    """SAST Benchmark"""
    if silent:
        os.environ["SILENT"] = "1"

cli.add_command(Coverity.cli)

if __name__ == '__main__':
    cli()