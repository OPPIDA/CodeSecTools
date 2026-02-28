"""Defines the SAST integration for Coverity.

This module provides the `CoveritySAST` class, which configures and orchestrates
the execution of Coverity scans using the core SAST framework.
"""

from pathlib import Path

from codesectools.sasts.core.sast import BuildlessSAST
from codesectools.sasts.core.sast.properties import SASTProperties
from codesectools.sasts.core.sast.requirements import Binary, SASTRequirements
from codesectools.sasts.tools.Coverity.parser import (
    CoverityAnalysisResult,
)


class CoveritySAST(BuildlessSAST):
    """SAST integration for Coverity.

    Attributes:
        name (str): The name of the SAST tool.
        supported_languages (list[str]): A list of supported programming languages.
        supported_dataset_names (list[str]): A list of names of compatible datasets.
        properties (SASTProperties): The properties of the SAST tool.
        requirements (SASTRequirements): The requirements for the SAST tool.
        commands (list[list[Union[str, tuple[str]]]]): The list of commands templates to be rendered and executed.
        valid_codes (list[int]): A list of exit codes indicating that the command did not fail.
        output_files (list[tuple[Path, bool]]): A list of expected output files and
            whether they are required.
        parser (type[CoverityAnalysisResult]): The parser class for the tool's results.

    """

    name = "Coverity"
    supported_languages = ["c", "java"]
    supported_dataset_names = ["BenchmarkJava", "CVEfixes"]
    properties = SASTProperties(free=False, offline=True)
    requirements = SASTRequirements(
        full_reqs=[
            Binary(
                "coverity",
                url="https://documentation.blackduck.com/bundle/coverity-docs/page/deploy-install-guide/topics/installing_coverity_analysis_components.html",
            ),
            Binary(
                "cov-analyze",
                url="https://documentation.blackduck.com/bundle/coverity-docs/page/deploy-install-guide/topics/installing_coverity_analysis_components.html",
            ),
            Binary(
                "cov-format-errors",
                url="https://documentation.blackduck.com/bundle/coverity-docs/page/deploy-install-guide/topics/installing_coverity_analysis_components.html",
            ),
        ],
        partial_reqs=[],
    )
    commands = [
        ["coverity", "capture", "--disable-build-command-inference"],
        ["cov-analyze", "--dir", "idir", "--all-security", "--disable-spotbugs"],
        ["cov-format-errors", "--dir", "idir", "--json-output-v10", "coverity.json"],
    ]
    valid_codes = [0]
    output_files = [(Path("coverity.json"), True)]
    parser = CoverityAnalysisResult
