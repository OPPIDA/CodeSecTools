"""Test dataset functionalities."""

import logging

from typer.testing import CliRunner

from codesectools.cli import cli
from codesectools.datasets import DATASETS_ALL

runner = CliRunner()


def test_datasets() -> None | AssertionError:
    """Test the download and caching of all datasets."""
    logging.info("Downloading all datasets")
    result = runner.invoke(
        cli, ["dataset", "download", "all"], input="y\n" * len(DATASETS_ALL.keys())
    )
    assert result.exit_code == 0

    for dataset_name, dataset in DATASETS_ALL.items():
        assert dataset.is_cached()
        for lang in dataset.supported_languages:
            logging.info(f"Testing dataset {dataset_name} for {lang}")
            dataset(lang=lang)

    result = runner.invoke(cli, ["status", "--datasets"])
    assert "❌" not in result.output
