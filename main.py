import os

import click

from sasts import SASTS_ALL


class OrderedGroup(click.Group):
    def list_commands(self, ctx: click.Context) -> list:
        return self.commands.keys()


@click.group(cls=OrderedGroup)
@click.option(
    "-d", "--debug", required=False, is_flag=True, help="Show debugging messages"
)
def cli(debug: bool) -> None:
    """SAST Benchmark"""
    if debug:
        os.environ["DEBUG"] = "1"


@cli.command()
def status() -> None:
    """Display SASTs and Datasets status"""
    raise NotImplementedError


for _, sast_components in SASTS_ALL.items():
    cli.add_command(sast_components["cli"])

if __name__ == "__main__":
    cli(prog_name="sastb")
