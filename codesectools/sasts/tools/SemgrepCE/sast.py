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
from codesectools.sasts.tools.SemgrepCE.parser import SemgrepCEAnalysisResult
from codesectools.utils import USER_CACHE_DIR


class SemgrepCESAST(BuildlessSAST):
    """SAST integration for Semgrep Community Edition.

    Attributes:
        name (str): The name of the SAST tool.
        supported_languages (list[str]): A list of supported programming languages.
        supported_dataset_names (list[str]): A list of names of compatible datasets.
        properties (SASTProperties): The properties of the SAST tool.
        requirements (SASTRequirements): The requirements for the SAST tool.
        commands (list[list[str]]): A list of command-line templates to be executed.
        output_files (list[tuple[Path, bool]]): A list of expected output files and
            whether they are required.
        parser (type[SemgrepCEAnalysisResult]): The parser class for the tool's results.
        color_mapping (dict): A mapping of result categories to colors for plotting.

    """

    name = "SemgrepCE"
    supported_languages = ["java"]
    supported_dataset_names = ["BenchmarkJava", "CVEfixes"]
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
            f"--config={str(USER_CACHE_DIR / 'semgrep-rules' / '{lang}')}",
            "--metrics=off",
            "--json-output=semgrepce_output.json",
        ]
    ]
    output_files = [
        (Path("semgrepce_output.json"), True),
    ]
    parser = SemgrepCEAnalysisResult
    color_mapping = {
        "HIGH": "RED",
        "MEDIUM": "ORANGE",
        "LOW": "YELLOW",
    }
