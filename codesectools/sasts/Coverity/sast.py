"""Defines the SAST integration for Coverity.

This module provides the `CoveritySAST` class, which configures and orchestrates
the execution of Coverity scans using the core SAST framework.
"""

from pathlib import Path

from codesectools.sasts.core.sast import SAST, Binary, Config, SASTRequirements
from codesectools.sasts.Coverity.parser import (
    COLOR_MAPPING,
    LANGUAGES,
    CoverityAnalysisResult,
)


class CoveritySAST(SAST):
    """SAST integration for Coverity.

    Attributes:
        name (str): The name of the SAST tool.
        supported_languages (list[str]): A list of supported programming languages.
        supported_dataset_names (list[str]): A list of names of compatible datasets.
        commands (list[list[str]]): A list of command-line templates to be executed.
        output_files (list[tuple[Path, bool]]): A list of expected output files and
            whether they are required.
        parser (type[CoverityAnalysisResult]): The parser class for the tool's results.
        color_mapping (dict): A mapping of result categories to colors for plotting.
        install_help_url (str): The URL for installation instructions.

    """

    name = "Coverity"
    supported_languages = LANGUAGES.keys()
    supported_dataset_names = ["SemgrepCERules", "BenchmarkJava", "CVEfixes"]
    requirements = SASTRequirements(
        full_reqs=[Binary("coverity"), Binary("cov-analyze")],
        partial_reqs=[Config("issueTypes.json"), Config("config.json")],
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
    output_files = [
        (Path("coverity.yaml"), False),
        (Path("idir", "coverity-cli", "capture-files-src-list*"), True),
        (Path("idir", "output", "*.xml"), False),
    ]
    parser = CoverityAnalysisResult
    color_mapping = COLOR_MAPPING
    install_help_url = "https://documentation.blackduck.com/bundle/coverity-docs/page/deploy-install-guide/topics/installing_coverity_analysis_components.html"
