"""Defines the SAST integration for Semgrep Community Edition.

This module provides the `SemgrepCESAST` class, which configures and orchestrates
the execution of Semgrep Community Edition scans using the core SAST framework.
"""

from pathlib import Path

from codesectools.datasets.SemgrepCERules.dataset import SemgrepCERules
from codesectools.sasts.core.sast import SAST
from codesectools.sasts.SemgrepCE.parser import SemgrepCEAnalysisResult
from codesectools.utils import USER_CACHE_DIR


class SemgrepCESAST(SAST):
    """SAST integration for Semgrep Community Edition."""

    name = "SemgrepCE"
    supported_languages = ["java"]
    supported_dataset_names = ["BenchmarkJava", "CVEfixes"]
    commands = (
        [
            [
                "semgrep",
                "scan",
                f"--config={str(USER_CACHE_DIR / SemgrepCERules.name / '{lang}')}",
                "--metrics=off",
                "--json-output=semgrep_output.json",
            ]
        ],
    )
    output_files = (
        [
            (Path("analysis.log"), True),
            (Path("semgrep_output.json"), True),
        ],
    )
    parser = SemgrepCEAnalysisResult
    color_mapping = {
        "security": "RED",
        "correctness": "ORANGE",
        "best-practice": "YELLOW",
        "performance": "GREEN",
        "maintainability": "CYAN",
        "portability": "GRAY",
    }
