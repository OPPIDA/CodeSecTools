"""Main entry point for the CodeSecTools application."""

from typer.main import get_command

from codesectools.cli import cli

click_cli = get_command(cli)

if __name__ == "__main__":
    cli()
