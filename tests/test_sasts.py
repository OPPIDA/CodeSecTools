"""Test SAST tool integrations."""

import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from codesectools.cli import cli
from codesectools.datasets import DATASETS_ALL
from codesectools.datasets.core.dataset import FileDataset, GitRepoDataset
from codesectools.sasts import SASTS_ALL

runner = CliRunner()

TEST_CODES = {
    "java": ("test.java", """System.out.print("Hello world!");"""),
}


def test_sasts() -> None | AssertionError:
    """Test the availability and help command for all SASTs."""
    for sast_name, sast_data in SASTS_ALL.items():
        sast_cli = sast_name.lower()
        result = runner.invoke(cli, [sast_cli, "--help"])
        if sast_data["available"]:
            assert result.exit_code == 0
            assert all(
                command in result.output
                for command in ["analyze", "results", "benchmark", "plot"]
            )
        else:
            assert result.exit_code == 2
            assert f"No such command '{sast_cli}'" in result.output


def test_sasts_analyze(monkeypatch: pytest.MonkeyPatch) -> None | AssertionError:
    """Test the 'analyze' command for all available SASTs."""
    for sast_name, sast_data in {
        k: v for k, v in SASTS_ALL.items() if v["available"]
    }.items():
        sast_cli = sast_name.lower()
        sast = sast_data["sast"]()
        for lang in sast.supported_languages:
            with tempfile.TemporaryDirectory() as temp_dir:
                monkeypatch.chdir(temp_dir)
                file_name, file_content = TEST_CODES[lang]
                Path(temp_dir, file_name).write_text(file_content)
                result = runner.invoke(cli, [sast_cli, "analyze", lang])
                print("ok")
                assert result.exit_code == 0
                assert "--overwrite" not in result.output

                for expected_files, required in sast.output_files:
                    if required:
                        assert (
                            sast.output_dir / Path(temp_dir).name / expected_files
                        ).is_file()

                result = runner.invoke(cli, [sast_cli, "analyze", lang])
                assert result.exit_code == 0
                assert "--overwrite" in result.output


def test_sasts_benchmark() -> None | AssertionError:
    """Test the 'benchmark' command for all available SASTs."""
    for sast_name, sast_data in {
        k: v for k, v in SASTS_ALL.items() if v["available"]
    }.items():
        sast_cli = sast_name.lower()
        sast = sast_data["sast"]()
        for dataset_full_name in sast.list_supported_datasets():
            result = runner.invoke(
                cli, [sast_cli, "benchmark", dataset_full_name, "--testing"]
            )
            assert result.exit_code == 0
            assert "--overwrite" not in result.output

            dataset_name, dataset_lang = dataset_full_name.split("_")
            dataset = DATASETS_ALL[dataset_name](lang=dataset_lang)

            if isinstance(dataset, FileDataset):
                for expected_files, required in sast.output_files:
                    if required:
                        assert (
                            sast.output_dir / dataset_full_name / expected_files
                        ).is_file()
            elif isinstance(dataset, GitRepoDataset):
                for repo in (sast.output_dir / dataset_full_name).iterdir():
                    for expected_files, required in sast.output_files:
                        if required:
                            assert (repo / expected_files).is_file()

            result = runner.invoke(
                cli, [sast_cli, "benchmark", dataset_full_name, "--testing"]
            )
            assert result.exit_code == 0
            assert "--overwrite" in result.output
