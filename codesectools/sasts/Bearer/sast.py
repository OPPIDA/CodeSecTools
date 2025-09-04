"""Define the SAST integration for Bearer.

This module provides the `BearerSAST` class, which configures and orchestrates
the execution of Bearer scans using the core SAST framework.
"""

from pathlib import Path

from codesectools.sasts.Bearer.parser import BearerAnalysisResult
from codesectools.sasts.core.sast import SAST
from codesectools.sasts.core.sast.properties import SASTProperties
from codesectools.sasts.core.sast.requirements import (
    Binary,
    GitRepo,
    SASTRequirements,
)
from codesectools.utils import USER_CACHE_DIR


class BearerSAST(SAST):
    """SAST integration for Bearer.

    Attributes:
        name (str): The name of the SAST tool.
        supported_languages (list[str]): A list of supported programming languages.
        supported_dataset_names (list[str]): A list of names of compatible datasets.
        properties (SASTProperties): The properties of the SAST tool.
        requirements (SASTRequirements): The requirements for the SAST tool.
        commands (list[list[str]]): A list of command-line templates to be executed.
        output_files (list[tuple[Path, bool]]): A list of expected output files and
            whether they are required.
        parser (type[BearerAnalysisResult]): The parser class for the tool's results.
        color_mapping (dict): A mapping of result categories to colors for plotting.

    """

    name = "Bearer"
    supported_languages = ["java"]
    supported_dataset_names = ["BenchmarkJava", "CVEfixes"]
    properties = SASTProperties(free=True, offline=True, buildless=True)
    requirements = SASTRequirements(
        full_reqs=[Binary("bearer", url="https://docs.bearer.com/quickstart/")],
        partial_reqs=[
            GitRepo(
                name="bearer-rules",
                repo_url="https://github.com/Bearer/bearer-rules.git",
                license="Elastic License 2.0",
                license_url="https://www.elastic.co/licensing/elastic-license",
            )
        ],
    )
    commands = [
        [
            "bearer",
            "scan",
            ".",
            "--force",
            "--disable-default-rules",
            f"--external-rule-dir={str(USER_CACHE_DIR / 'bearer-rules' / 'rules' / '{lang}')}",
            "--scanner=sast",
            "--format=json",
            "--output=bearer_output.json",
            "--disable-version-check",
        ]
    ]
    output_files = [
        (Path("bearer_output.json"), True),
    ]
    parser = BearerAnalysisResult
    color_mapping = {
        "critical": "red",
        "high": "orangered",
        "medium": "orange",
        "low": "gold",
        "warning": "yellow",
    }
