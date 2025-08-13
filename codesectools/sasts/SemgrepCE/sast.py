"""Defines the SAST integration for Semgrep Community Edition.

This module provides the `SemgrepCESAST` class, which configures and orchestrates
the execution of Semgrep Community Edition scans using the core SAST framework.
"""

from pathlib import Path

from codesectools.sasts.core.sast import SAST
from codesectools.sasts.SemgrepCE.constants import (
    COLOR_MAPPING,
    LANGUAGES,
    SUPPORTED_DATASETS,
)
from codesectools.sasts.SemgrepCE.parser import SemgrepCEAnalysisResult


class SemgrepCESAST(SAST):
    """Implements the SAST interface for Semgrep Community Edition.

    This class specifies the commands, expected output files, result parser,
    and supported configurations for running Semgrep Community Edition.

    Attributes:
        name (str): The name of the SAST tool, "SemgrepCE".

    """

    name = "SemgrepCE"

    def __init__(self) -> None:
        """Initialize the SemgrepCESAST integration."""
        super().__init__(
            commands=[
                "semgrep scan --config=p/{lang} --metrics=off --json-output=semgrep_output.json --jobs=4".split(
                    " "
                )
            ],
            analysis_files=[
                (Path("analysis.log"), True),
                (Path("semgrep_output.json"), True),
            ],
            parser=SemgrepCEAnalysisResult,
            supported_languages=LANGUAGES.keys(),
            supported_datasets=SUPPORTED_DATASETS,
            color_mapping=COLOR_MAPPING,
        )
