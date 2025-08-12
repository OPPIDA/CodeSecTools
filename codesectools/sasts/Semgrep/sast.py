"""Defines the SAST integration for Semgrep.

This module provides the `SemgrepSAST` class, which configures and orchestrates
the execution of Semgrep scans using the core SAST framework.
"""

from pathlib import Path

from codesectools.sasts.core.sast import SAST
from codesectools.sasts.Semgrep.constants import (
    COLOR_MAPPING,
    LANGUAGES,
    SUPPORTED_DATASETS,
)
from codesectools.sasts.Semgrep.parser import SemgrepAnalysisResult


class SemgrepSAST(SAST):
    """Implements the SAST interface for Semgrep.

    This class specifies the commands, expected output files, result parser,
    and supported configurations for running Semgrep Pro.

    Attributes:
        name (str): The name of the SAST tool, "Semgrep".

    """

    name = "Semgrep"

    def __init__(self) -> None:
        """Initialize the SemgrepSAST integration."""
        super().__init__(
            commands=[
                "semgrep scan --config=p/{lang} --pro --metrics=off --json-output=output.json --jobs=4".split(
                    " "
                )
            ],
            analysis_files=[(Path("analysis.log"), True), (Path("output.json"), True)],
            parser=SemgrepAnalysisResult,
            supported_languages=LANGUAGES.keys(),
            supported_datasets=SUPPORTED_DATASETS,
            color_mapping=COLOR_MAPPING,
        )
