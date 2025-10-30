"""Defines the SAST integration for Coverity.

This module provides the `CoveritySAST` class, which configures and orchestrates
the execution of Coverity scans using the core SAST framework.
"""

from pathlib import Path

from codesectools.sasts.core.sast import BuildlessSAST
from codesectools.sasts.core.sast.properties import SASTProperties
from codesectools.sasts.core.sast.requirements import Binary, Config, SASTRequirements
from codesectools.sasts.tools.Coverity.parser import (
    COLOR_MAPPING,
    LANGUAGES,
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
        commands (list[list[str]]): A list of command-line templates to be executed.
        valid_codes (list[int]): A list of exit codes indicating that the command did not fail.
        output_files (list[tuple[Path, bool]]): A list of expected output files and
            whether they are required.
        parser (type[CoverityAnalysisResult]): The parser class for the tool's results.
        color_mapping (dict): A mapping of result categories to colors for plotting.

    """

    name = "Coverity"
    supported_languages = LANGUAGES.keys()
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
        ],
        partial_reqs=[
            Config("issueTypes.json", doc=True),
            Config("config.json", doc=True),
        ],
    )
    commands = [
        [
            "coverity",
            "capture",
            "--disable-build-command-inference",
            "--language",
            "{lang}",
        ],
        [
            "cov-analyze",
            "--dir",
            "idir",
            "--all-security",
            "--enable-callgraph-metrics",
        ],
    ]
    valid_codes = [0]
    output_files = [
        (Path("coverity.yaml"), False),
        (Path("idir", "coverity-cli", "capture-files-src-list*"), True),
        (Path("idir", "output", "*.xml"), False),
    ]
    parser = CoverityAnalysisResult
    color_mapping = COLOR_MAPPING
