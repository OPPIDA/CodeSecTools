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
        extra_languages (list[str]): Languages supported by the tool itself but not codesectools.
        supported_dataset_names (list[str]): A list of names of compatible datasets.
        properties (SASTProperties): The properties of the SAST tool.
        requirements (SASTRequirements): The requirements for the SAST tool.
        commands (list[list[Union[str, tuple[str]]]]): The list of commands templates to be rendered and executed.
        valid_codes (list[int]): A list of exit codes indicating that the command did not fail.
        output_files (list[tuple[Path, bool]]): A list of expected output files and
            whether they are required.
        parser (type[SnykCodeAnalysisResult]): The parser class for the tool's results.

    """

    name = "SnykCode"
    supported_languages = ["java", "c"]
    extra_languages = [
        "apex",
        "dart",
        "elixir",
        "go",
        "groovy",
        "java",
        "kotlin",
        "javascript",
        "csharp",
        "php",
        "python",
        "ruby",
        "rust",
        "scala",
        "swift",
        "objective-c",
        "typescript",
    ]
    supported_dataset_names = ["BenchmarkJava", "CVEfixes", "JulietTestSuiteC"]
    properties = SASTProperties(free=False, offline=False)
    requirements = SASTRequirements(
        full_reqs=[
            Binary(
                "snyk",
                url="https://docs.snyk.io/developer-tools/snyk-cli/install-or-update-the-snyk-cli",
            ),
            Config("auth_token.txt", doc=True, sast_name=name),
        ],
        partial_reqs=[],
    )
    commands = [["snyk", "code", "test", "--sarif-file-output=snykcode.sarif"]]
    valid_codes = [
        0,
        1,
    ]  # https://docs.snyk.io/developer-tools/snyk-cli/commands/code-test#exit-codes
    output_files = [
        (Path("snykcode.sarif"), False),
    ]
    parser = SnykCodeAnalysisResult

    def __init__(self) -> None:
        """Initialize the SnykCodeSAST instance.

        Reads the Snyk authentication token from a user configuration file and
        sets it in the environment for subsequent commands.

        """
        super().__init__()
        snyk_token = USER_CONFIG_DIR / "SnykCode" / "auth_token.txt"
        if snyk_token.is_file():
            self.environ["SNYK_TOKEN"] = snyk_token.read_text()
