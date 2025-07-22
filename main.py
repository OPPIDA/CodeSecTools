import SASTs.Coverity.cli as Coverity
import SASTs.Semgrep.cli as Semgrep
from utils import *


@click.group()
@click.option("--silent", required=False, is_flag=True, help="")
def cli(silent):
    """SAST Benchmark"""
    if silent:
        os.environ["SILENT"] = "1"


cli.add_command(Coverity.cli)
cli.add_command(Semgrep.cli)

if __name__ == "__main__":
    cli()
