"""Defines the SAST integration for Semgrep Community Edition.

This module provides the `SemgrepCESAST` class, which configures and orchestrates
the execution of Semgrep Community Edition scans using the core SAST framework.
"""

from pathlib import Path

from codesectools.sasts.core.sast import BuildlessSAST
from codesectools.sasts.core.sast.properties import SASTProperties
from codesectools.sasts.core.sast.requirements import (
    Binary,
    GitRepo,
    SASTRequirements,
)
from codesectools.sasts.tools.SemgrepCE.parser import (
    SEMGREP_RULES_DIR,
    SemgrepCEAnalysisResult,
)


class SemgrepCESAST(BuildlessSAST):
    """SAST integration for Semgrep Community Edition.

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
        parser (type[SemgrepCEAnalysisResult]): The parser class for the tool's results.

    """

    name = "SemgrepCE"
    supported_languages = ["java", "c"]
    extra_languages = [
        "csharp",
        "go",
        "javascript",
        "kotlin",
        "python",
        "typescript",
        "jsx",
        "ruby",
        "scala",
        "swift",
        "rust",
        "php",
    ]
    supported_dataset_names = ["BenchmarkJava", "CVEfixes", "JulietTestSuiteC"]
    properties = SASTProperties(free=True, offline=True)
    requirements = SASTRequirements(
        full_reqs=[
            Binary("semgrep", url="https://semgrep.dev/docs/getting-started/quickstart")
        ],
        partial_reqs=[
            GitRepo(
                name="semgrep-rules",
                repo_url="https://github.com/semgrep/semgrep-rules.git",
                license="Semgrep Rules License v. 1.0",
                license_url="https://semgrep.dev/legal/rules-license/",
            )
        ],
    )
    commands = [
        [
            "semgrep",
            "scan",
            f"--config={str(SEMGREP_RULES_DIR / '{lang}')}",
            "--metrics=off",
            "--sarif",
            "--sarif-output=semgrepce.sarif",
        ]
    ]
    valid_codes = [0, 1]  # https://semgrep.dev/docs/cli-reference#exit-codes
    output_files = [
        (Path("semgrepce.sarif"), True),
    ]
    parser = SemgrepCEAnalysisResult
