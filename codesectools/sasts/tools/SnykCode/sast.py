"""Defines the SAST integration for Snyk Code.

This module provides the `SnykCodeSAST` class, which configures and orchestrates
the execution of Snyk Code scans using the core SAST framework.
"""

from pathlib import Path

from codesectools.sasts.core.sast import BuildlessSAST
from codesectools.sasts.core.sast.properties import SASTProperties
from codesectools.sasts.core.sast.requirements import Binary, Config, SASTRequirements
from codesectools.sasts.tools.SnykCode.parser import SnykCodeAnalysisResult
from codesectools.utils import USER_CONFIG_DIR


class SnykCodeSAST(BuildlessSAST):
    """SAST integration for Snyk Code.

    Attributes:
        name (str): The name of the SAST tool.
        supported_languages (list[str]): A list of supported programming languages.
        supported_dataset_names (list[str]): A list of names of compatible datasets.
        properties (SASTProperties): The properties of the SAST tool.
        requirements (SASTRequirements): The requirements for the SAST tool.
        commands (list[list[str]]): A list of command-line templates to be executed.
        output_files (list[tuple[Path, bool]]): A list of expected output files and
            whether they are required.
        parser (type[SnykCodeAnalysisResult]): The parser class for the tool's results.
        color_mapping (dict): A mapping of result categories to colors for plotting.

    """

    name = "SnykCode"
    supported_languages = ["java"]
    supported_dataset_names = ["BenchmarkJava", "CVEfixes"]
    properties = SASTProperties(free=False, offline=False)
    requirements = SASTRequirements(
        full_reqs=[
            Binary(
                "snyk",
                url="https://docs.snyk.io/developer-tools/snyk-cli/install-or-update-the-snyk-cli",
            ),
            Config("auth_token.txt", doc=True),
        ],
        partial_reqs=[],
    )
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

    def __init__(self) -> None:
        """Initialize the SnykCodeSAST instance.

        Reads the Snyk authentication token from a user configuration file and
        sets it in the environment for subsequent commands.

        """
        super().__init__()
        snyk_token = USER_CONFIG_DIR / "SnykCode" / "auth_token.txt"
        if snyk_token.is_file():
            self.environ["SNYK_TOKEN"] = snyk_token.read_text()
