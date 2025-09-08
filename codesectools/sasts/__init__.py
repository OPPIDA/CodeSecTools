"""Dynamically discovers and registers all available SAST integrations.

This module iterates through the subdirectories of the `codesectools/sasts`
directory. For each subdirectory that represents a SAST tool (i.e., contains a
`sast.py` file and is not the `core` directory), it dynamically imports the
necessary components (SAST class, AnalysisResult class, and Typer CLI application)
and adds them to the `SASTS_ALL` dictionary.

Attributes:
    SASTS_ALL (dict): A dictionary mapping SAST tool names to their associated data.
        Each value is a dictionary containing the tool's 'status', a list of
        'missing' requirements, its 'properties', the 'sast' class, the
        'analysis_result' class, and the 'cli_factory'.

"""

import importlib

import typer

from codesectools.sasts.core.sast import SAST, AnalysisResult
from codesectools.utils import SASTS_DIR

SASTS_ALL = {}
for child in SASTS_DIR.iterdir():
    if child.is_dir():
        if list(child.glob("sast.py")) and child.name not in ["all", "core"]:
            sast_name = child.name

            sast_module = importlib.import_module(
                f"codesectools.sasts.{sast_name}.sast"
            )

            sast: SAST = getattr(sast_module, f"{sast_name}SAST")
            sast_instance = sast()
            analysis_result: AnalysisResult = getattr(
                sast_module, f"{sast_name}AnalysisResult"
            )

            cli_module = importlib.import_module(f"codesectools.sasts.{sast_name}.cli")
            cli_factory: typer.Typer = getattr(cli_module, f"{sast_name}CLIFactory")

            SASTS_ALL[sast_name] = {
                "status": sast_instance.status,
                "missing": sast_instance.missing,
                "properties": sast_instance.properties,
                "sast": sast,
                "analysis_result": analysis_result,
                "cli_factory": cli_factory,
            }

SASTS_ALL = dict(sorted(SASTS_ALL.items()))
