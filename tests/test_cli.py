"""Test the main CLI commands."""

import logging

from typer.testing import CliRunner

from codesectools.cli import cli, get_downloadable
from codesectools.datasets import DATASETS_ALL

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


def test_download() -> None | AssertionError:
    """Test the download of missing resources."""
    logging.info("Downloading all missing resources")
    result = runner.invoke(
        cli, ["download", "all"], input="y\n" * len(get_downloadable())
    )
    assert result.exit_code == 0

    for dataset_name, dataset in DATASETS_ALL.items():
        assert dataset.is_cached()
        for lang in dataset.supported_languages:
            logging.info(f"Testing dataset {dataset_name} for {lang}")
            dataset(lang=lang)

    result = runner.invoke(cli, ["status", "--datasets"])
    assert "❌" not in result.output
