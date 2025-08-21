"""Test dataset functionalities."""

import logging

from typer.testing import CliRunner

from codesectools.cli import cli
from codesectools.datasets import DATASETS_ALL

runner = CliRunner()


def test_datasets() -> None | AssertionError:
    """Test the download and caching of all datasets."""
    for dataset_name, dataset in DATASETS_ALL.items():
        for lang in dataset.supported_languages:
            logging.info(f"Caching dataset {dataset_name} for {lang} language")
            dataset(lang=lang)

        assert dataset.is_cached()

    result = runner.invoke(cli, ["status", "--datasets"])
    assert "❌" not in result.output
