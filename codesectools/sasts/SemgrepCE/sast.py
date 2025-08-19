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
    """SAST integration for Semgrep Community Edition.

    Attributes:
        name (str): The name of the SAST tool.
        supported_languages (list[str]): A list of supported programming languages.
        supported_dataset_names (list[str]): A list of names of compatible datasets.
        commands (list[list[str]]): A list of command-line templates to be executed.
        output_files (list[tuple[Path, bool]]): A list of expected output files and
            whether they are required.
        parser (type[SemgrepCEAnalysisResult]): The parser class for the tool's results.
        color_mapping (dict): A mapping of result categories to colors for plotting.

    """

    name = "SemgrepCE"
    supported_languages = ["java"]
    supported_dataset_names = ["BenchmarkJava", "CVEfixes"]
    commands = [
        [
            "semgrep",
            "scan",
            f"--config={str(USER_CACHE_DIR / SemgrepCERules.name / '{lang}')}",
            "--metrics=off",
            "--json-output=semgrep_output.json",
        ]
    ]
    output_files = [
        (Path("analysis.log"), True),
        (Path("semgrep_output.json"), True),
    ]
    parser = SemgrepCEAnalysisResult
    color_mapping = {
        "security": "RED",
        "correctness": "ORANGE",
        "best-practice": "YELLOW",
        "performance": "GREEN",
        "maintainability": "CYAN",
        "portability": "GRAY",
    }

    def __init__(self) -> None:
        """Initialize the SemgrepCESAST instance.

        This constructor automatically downloads the Semgrep Community Edition rules
        required for analysis by initializing the `SemgrepCERules` dataset for each
        supported language.
        """
        super().__init__()
        for lang in self.supported_languages:
            SemgrepCERules(lang=lang)  # Download rules during initialization
