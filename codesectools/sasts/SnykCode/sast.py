"""Defines the SAST integration for Snyk Code.

This module provides the `SnykCodeSAST` class, which configures and orchestrates
the execution of Snyk Code scans using the core SAST framework.
"""

from pathlib import Path

from codesectools.sasts.core.sast import SAST
from codesectools.sasts.SnykCode.parser import SnykCodeAnalysisResult
from codesectools.utils import USER_CONFIG_DIR, MissingFile


class SnykCodeSAST(SAST):
    """SAST integration for Snyk Code.

    Attributes:
        name (str): The name of the SAST tool.
        supported_languages (list[str]): A list of supported programming languages.
        supported_dataset_names (list[str]): A list of names of compatible datasets.
        commands (list[list[str]]): A list of command-line templates to be executed.
        output_files (list[tuple[Path, bool]]): A list of expected output files and
            whether they are required.
        parser (type[SnykCodeAnalysisResult]): The parser class for the tool's results.
        color_mapping (dict): A mapping of result categories to colors for plotting.
        install_help_url (str): The URL for installation instructions.

    """

    name = "SnykCode"
    supported_languages = ["java"]
    supported_dataset_names = ["SemgrepCERules", "BenchmarkJava", "CVEfixes"]
    commands = [["snyk", "code", "test", "--json-file-output=snyk_results.json"]]
    output_files = [
        (Path("snyk_results.json"), False),
    ]
    parser = SnykCodeAnalysisResult
    color_mapping = {
        "error": "red",
        "warning": "orange",
        "note": "yellow",
        "info": "yellow",
    }
    install_help_url = (
        "https://docs.snyk.io/developer-tools/snyk-cli/install-or-update-the-snyk-cli"
    )

    def __init__(self) -> None:
        """Initialize the SnykCodeSAST instance.

        Reads the Snyk authentication token from a user configuration file and
        sets it in the environment for subsequent commands.

        Raises:
            MissingFile: If the Snyk token file `auth_token.txt` is not found.

        """
        super().__init__()
        snyk_token = USER_CONFIG_DIR / "SnykCode" / "auth_token.txt"
        if snyk_token.is_file():
            self.environ["SNYK_TOKEN"] = snyk_token.read_text()
        else:
            raise MissingFile(["auth_token.txt"])
