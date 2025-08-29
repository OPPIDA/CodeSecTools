"""Test SAST integration functionalities."""

import logging
import tempfile
from pathlib import Path
from types import GeneratorType

import pytest
from typer.testing import CliRunner

from codesectools.datasets import DATASETS_ALL
from codesectools.datasets.core.dataset import FileDataset, GitRepoDataset
from codesectools.sasts import SASTS_ALL


@pytest.fixture(autouse=True, scope="module")
def reload_sast_module_state() -> GeneratorType:
    """Reset the state of SAST modules before running tests."""
    for sast_data in SASTS_ALL.values():
        sast_instance = sast_data["sast"]()
        sast_data["cli_factory"].sast.__init__()
        sast_data["status"] = sast_instance.status
        sast_data["missing"] = sast_instance.missing

    yield


runner = CliRunner(env={"COLUMNS": "200"})

TEST_CODES = {
    "java": (
        "test.java",
        """import java.io.BufferedReader;
import java.io.InputStreamReader;
BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
String userInput = br.readLine();
Runtime.getRuntime().exec("ping -c 1 " + userInput);""",
    ),
}


def test_included() -> None:
    """Ensure that specific SASTs are fully available for testing."""
    included_sasts = ["SemgrepCE"]
    for included_sast in included_sasts:
        sast_data = SASTS_ALL[included_sast]
        if sast_data["status"] != "full":
            pytest.fail(f"{sast_data['missing']} are missing for {included_sast}")


def test_sasts() -> None | AssertionError:
    """Test the availability and help command for all SASTs."""
    for sast_name, sast_data in SASTS_ALL.items():
        logging.info(f"Checking {sast_name} commands")
        sast_cli = sast_data["cli_factory"].build_cli()
        result = runner.invoke(sast_cli, ["--help"])
        if sast_data["status"] == "full":
            assert result.exit_code == 0
            assert all(
                command in result.output
                for command in ["analyze", "benchmark", "list", "plot"]
            )
        elif sast_data["status"] == "partial":
            assert result.exit_code == 0
            assert all(
                command in result.output for command in ["install", "list", "plot"]
            )
        elif sast_data["status"] == "none":
            assert result.exit_code == 0
            assert all(command in result.output for command in ["install"])
        else:
            assert result.exit_code != 0


SAST_RESULTS = {sast_name: [] for sast_name in SASTS_ALL}


def test_sasts_analyze(monkeypatch: pytest.MonkeyPatch) -> None | AssertionError:
    """Test the 'analyze' command for all available SASTs."""
    for sast_name, sast_data in SASTS_ALL.items():
        if sast_data["status"] != "full":
            continue
        sast_cli = sast_data["cli_factory"].build_cli()
        sast = sast_data["sast"]()
        for lang in sast.supported_languages:
            logging.info(f"Testing {sast_name} analyze command on {lang} code")
            with tempfile.TemporaryDirectory() as temp_dir:
                monkeypatch.chdir(temp_dir)
                file_name, file_content = TEST_CODES[lang]
                Path(temp_dir, file_name).write_text(file_content)
                result = runner.invoke(sast_cli, ["analyze", lang])
                assert result.exit_code == 0
                assert "--overwrite" not in result.output

                for expected_files, required in sast.output_files:
                    if required:
                        assert (
                            sast.output_dir / Path(temp_dir).name / expected_files
                        ).is_file()

                SAST_RESULTS[sast_name].append(Path(temp_dir).name)

                result = runner.invoke(sast_cli, ["analyze", lang])
                assert result.exit_code == 0
                assert "--overwrite" in result.output


def test_sasts_benchmark() -> None | AssertionError:
    """Test the 'benchmark' command for all available SASTs."""
    for sast_name, sast_data in SASTS_ALL.items():
        if sast_data["status"] != "full":
            continue
        sast_cli = sast_data["cli_factory"].build_cli()
        sast = sast_data["sast"]()
        for dataset_full_name in sast.supported_dataset_full_names:
            logging.info(
                f"Testing {sast_name} benchmark command on {dataset_full_name}"
            )
            result = runner.invoke(
                sast_cli, ["benchmark", dataset_full_name, "--testing"]
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
                SAST_RESULTS[sast_name].append(dataset_full_name)
            elif isinstance(dataset, GitRepoDataset):
                for repo in (sast.output_dir / dataset_full_name).iterdir():
                    for expected_files, required in sast.output_files:
                        if required:
                            assert (repo / expected_files).is_file()
                SAST_RESULTS[sast_name].append(dataset_full_name)
            result = runner.invoke(
                sast_cli, ["benchmark", dataset_full_name, "--testing"]
            )
            assert result.exit_code == 0
            assert "--overwrite" in result.output


def test_sasts_list() -> None | AssertionError:
    """Test the 'list' command for all available SASTs."""
    for sast_name, sast_data in SASTS_ALL.items():
        if sast_data["status"] != "full":
            continue
        sast_cli = sast_data["cli_factory"].build_cli()
        result = runner.invoke(sast_cli, ["list"])
        assert result.exit_code == 0
        for sast_result in SAST_RESULTS[sast_name]:
            logging.info(
                f"Checking {sast_name} list command contains {sast_result} from previous commands"
            )
            assert sast_result in result.output


def test_sasts_plot() -> None | AssertionError:
    """Test the 'plot' command for all available SASTs."""
    for sast_name, sast_data in SASTS_ALL.items():
        if sast_data["status"] != "full":
            continue
        sast = sast_data["sast"]()
        sast_cli = sast_data["cli_factory"].build_cli()

        for sast_result in SAST_RESULTS[sast_name]:
            logging.info(f"Testing {sast_name} plot command on {sast_result}")
            result = runner.invoke(sast_cli, ["plot", sast_result])
            assert result.exit_code == 0
            assert (sast.output_dir / sast_result / "_figures").is_dir()
