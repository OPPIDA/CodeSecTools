"""Defines the SAST integration for Coverity.

This module provides the `CoveritySAST` class, which configures and orchestrates
the execution of Coverity scans using the core SAST framework.
"""

from pathlib import Path

from codesectools.sasts.core.sast import SAST
from codesectools.sasts.Coverity.config import COLOR_MAPPING, LANGUAGES
from codesectools.sasts.Coverity.parser import CoverityAnalysisResult


class CoveritySAST(SAST):
    """SAST integration for Coverity."""

    name = "Coverity"
    supported_languages = LANGUAGES.keys()
    supported_dataset_names = ["SemgrepCERules", "BenchmarkJava", "CVEfixes"]
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
