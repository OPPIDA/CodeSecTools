"""Test the 'allsast' command integration."""

import logging
from types import GeneratorType

import git
import pytest
from typer.testing import CliRunner

from codesectools.sasts import SASTS_ALL
from codesectools.sasts.all.cli import build_cli
from codesectools.sasts.all.sast import AllSAST

all_sast = AllSAST()


@pytest.fixture(autouse=True, scope="module")
def update_sast_module_state() -> GeneratorType:
    """Update the state of SAST modules before running tests in this module."""
    for sast_data in SASTS_ALL.values():
        sast_instance = sast_data["sast"]()
        sast_data["cli_factory"].sast.__init__()
        sast_data["status"] = sast_instance.status
        sast_data["missing"] = sast_instance.missing

    yield


runner = CliRunner(env={"COLUMNS": "200"})


def test_included() -> None:
    """Ensure that all free and offline SASTs are available for testing."""
    for sast_name, sast_data in SASTS_ALL.items():
        sast_properties = sast_data["properties"]
        if sast_properties.free and sast_properties.offline:
            if sast_data["status"] != "full":
                pytest.fail(f"{sast_data['missing']} are missing for {sast_name}")


def test_analyze(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test the 'allsast analyze' command."""
    logging.info("Testing All SAST analyze command on Java code")  # Support Java only
    git.Repo.clone_from("https://github.com/appsecco/dvja.git", "/tmp/dvja")
    monkeypatch.chdir("/tmp/dvja")
    result = runner.invoke(build_cli(), ["analyze", "java"])
    assert result.exit_code == 0


def test_list() -> None:
    """Test the 'allsast list' command."""
    logging.info("Testing All SAST list command on Java code")
    result = runner.invoke(build_cli(), ["list"])
    assert result.exit_code == 0
    assert "dvja" in result.output


def test_plot() -> None:
    """Test the 'allsast plot' command."""
    logging.info("Testing All SAST plot command on Java code")
    result = runner.invoke(build_cli(), ["plot", "dvja"])
    assert result.exit_code == 0
    assert (all_sast.output_dir / "dvja" / "_figures").is_dir()


def test_report() -> None:
    """Test the 'allsast report' command."""
    logging.info("Testing All SAST report command on Java code")
    result = runner.invoke(build_cli(), ["report", "dvja"])
    assert result.exit_code == 0
    assert (all_sast.output_dir / "dvja" / "report").is_dir()
    assert list((all_sast.output_dir / "dvja" / "report").glob("*.html"))
