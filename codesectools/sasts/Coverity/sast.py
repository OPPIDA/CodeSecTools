"""Defines the SAST integration for Synopsys Coverity.

This module provides the `CoveritySAST` class, which configures and orchestrates
the execution of Coverity scans using the core SAST framework.
"""

from pathlib import Path

from codesectools.sasts.core.sast import SAST
from codesectools.sasts.Coverity.constants import (
    COLOR_MAPPING,
    LANGUAGES,
    SUPPORTED_DATASETS,
)
from codesectools.sasts.Coverity.parser import CoverityAnalysisResult


class CoveritySAST(SAST):
    """Implements the SAST interface for Coverity.

    This class specifies the commands, expected output files, result parser,
    and supported configurations for running Coverity.

    Attributes:
        name (str): The name of the SAST tool, "Coverity".

    """

    name = "Coverity"

    def __init__(self) -> None:
        """Initialize the CoveritySAST integration."""
        super().__init__(
            commands=[
                "coverity capture --disable-build-command-inference --language {lang}".split(
                    " "
                ),
                "cov-analyze --dir idir --all-security --enable-callgraph-metrics".split(
                    " "
                ),
            ],
            output_files=[
                (Path("coverity.yaml"), False),
                (Path("idir", "coverity-cli", "capture-files-src-list*"), True),
                (Path("idir", "output", "*.xml"), False),
            ],
            parser=CoverityAnalysisResult,
            supported_languages=LANGUAGES.keys(),
            supported_datasets=SUPPORTED_DATASETS,
            color_mapping=COLOR_MAPPING,
        )
