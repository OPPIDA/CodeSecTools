"""Test the main CLI commands."""

import logging

import pytest
from typer.testing import CliRunner

from codesectools.cli import cli, get_downloadable
from codesectools.sasts.core.sast.requirements import DownloadableRequirement

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


@pytest.mark.order(0)
def test_download() -> None | AssertionError:
    """Test the download of missing resources."""
    downloadable = get_downloadable()
    logging.info("Downloading all missing resources.")
    result = runner.invoke(
        cli, ["download", "all", "--test"], input="y\n" * len(downloadable)
    )
    assert result.exit_code == 0

    for name, instance in downloadable.items():
        logging.info(f"Check if {name} is cached.")
        if isinstance(instance, DownloadableRequirement):
            assert instance.is_fulfilled()
        else:
            assert instance.is_cached()

    result = runner.invoke(cli, ["status", "--datasets"])
    assert "❌" not in result.output
