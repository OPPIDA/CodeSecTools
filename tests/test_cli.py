"""Test the main CLI commands."""

from typer.testing import CliRunner

from codesectools.cli import cli

runner = CliRunner(env={"COLUMNS": "200"})


def test_help() -> None | AssertionError:
    """Test the '--help' option."""
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "version" in result.output
    assert "status" in result.output


def test_version() -> None | AssertionError:
    """Test the 'version' command."""
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0


def test_status() -> None | AssertionError:
    """Test the 'status' command."""
    result = runner.invoke(cli, ["status"])
    assert result.exit_code == 0
