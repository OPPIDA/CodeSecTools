"""Defines the SAST integration for SpotBugs.

This module provides the `SpotBugsSAST` class, which configures and orchestrates
the execution of SpotBugs scans using the core SAST framework.
"""

import shutil
from pathlib import Path

from codesectools.sasts.core.sast import PrebuiltSAST
from codesectools.sasts.core.sast.properties import SASTProperties
from codesectools.sasts.core.sast.requirements import (
    Binary,
    File,
    SASTRequirements,
)
from codesectools.sasts.tools.SpotBugs.parser import SpotBugsAnalysisResult


class SpotBugsSAST(PrebuiltSAST):
    """SAST integration for SpotBugs.

    Attributes:
        name (str): The name of the SAST tool.
        supported_languages (list[str]): A list of supported programming languages.
        supported_dataset_names (list[str]): A list of names of compatible datasets.
        properties (SASTProperties): The properties of the SAST tool.
        requirements (SASTRequirements): The requirements for the SAST tool.
        commands (list[list[str]]): A list of command-line templates to be executed.
        output_files (list[tuple[Path, bool]]): A list of expected output files and
            whether they are required.
        parser (type[SpotBugsAnalysisResult]): The parser class for the tool's results.
        color_mapping (dict): A mapping of result categories to colors for plotting.

    """

    name = "SpotBugs"
    supported_languages = ["java"]
    supported_dataset_names = ["BenchmarkJava"]
    properties = SASTProperties(free=True, offline=True)
    requirements = SASTRequirements(
        full_reqs=[
            Binary("spotbugs", url="https://github.com/spotbugs/spotbugs"),
            File(
                name="findsecbugs-plugin-1.14.0.jar",
                parent_dir=Path(shutil.which("spotbugs")).parent.parent / "plugin",
                file_url="https://search.maven.org/remotecontent?filepath=com/h3xstream/findsecbugs/findsecbugs-plugin/1.14.0/findsecbugs-plugin-1.14.0.jar",
                license="LGPL-3.0",
                license_url="https://find-sec-bugs.github.io/license.htm",
            ),
        ],
        partial_reqs=[],
    )
    commands = [
        [
            "spotbugs",
            "-textui",
            "-nested:true",
            "-progress",
            "-sarif=spotbugs_output.json",
            "{artifact_dir}",
        ]
    ]
    output_files = [
        (Path("spotbugs_output.json"), True),
    ]
    parser = SpotBugsAnalysisResult
    # Based on: spotbugs/spotbugs/etc/bugrank.txt
    color_mapping = {
        "SECURITY": "red",
        "CORRECTNESS": "orange",
        "MT_CORRECTNESS": "yellow",
    }
