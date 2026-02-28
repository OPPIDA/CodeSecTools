"""Defines the SAST integration for Cppcheck.

This module provides the `CppcheckSAST` class, which configures and orchestrates
the execution of Cppcheck scans using the core SAST framework.
"""

from pathlib import Path

from codesectools.sasts.core.sast import PrebuiltBuildlessSAST
from codesectools.sasts.core.sast.properties import SASTProperties
from codesectools.sasts.core.sast.requirements import (
    Binary,
    BinaryVersion,
    SASTRequirements,
)
from codesectools.sasts.tools.Cppcheck.parser import CppcheckAnalysisResult
from codesectools.utils import CPU_COUNT


class CppcheckSAST(PrebuiltBuildlessSAST):
    """SAST integration for Cppcheck.

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
        parser (type[CppcheckAnalysisResult]): The parser class for the tool's results.

    """

    name = "Cppcheck"
    supported_languages = ["c"]
    supported_dataset_names = ["JulietTestSuiteC"]
    properties = SASTProperties(free=True, offline=True)
    requirements = SASTRequirements(
        full_reqs=[
            Binary(
                "cppcheck",
                url="https://cppcheck.sourceforge.io/",
                version=BinaryVersion("--version", r"(\d+\.\d+\.\d+)", "2.16.0"),
            ),
        ],
        partial_reqs=[],
    )
    commands = [
        [
            "cppcheck",
            (".", "--project={artifacts}"),
            "--enable=all",
            "--output-format=sarif",
            "--output-file=cppcheck.sarif",
            "--cppcheck-build-dir={tempdir}",
            f"-j{CPU_COUNT}",
        ]
    ]
    valid_codes = [0]
    output_files = [
        (Path("cppcheck.sarif"), True),
    ]
    parser = CppcheckAnalysisResult

    # PrebuiltSAST
    artifact_name = "Compilation database"
    artifact_type = "file"
