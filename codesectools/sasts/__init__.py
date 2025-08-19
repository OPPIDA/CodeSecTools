"""Dynamically discovers and registers all available SAST integrations.

This module iterates through the subdirectories of the `codesectools/sasts`
directory. For each subdirectory that represents a SAST tool (i.e., contains a
`sast.py` file and is not the `core` directory), it dynamically imports the
necessary components (SAST class, AnalysisResult class, and Typer CLI application)
and adds them to the `SASTS_ALL` dictionary.

Attributes:
    SASTS_ALL (dict): A dictionary mapping SAST tool names to their components,
        including the SAST implementation, the result parser, and the CLI command group.

"""

import importlib

import typer

from codesectools.sasts.core.sast import SAST, AnalysisResult
from codesectools.utils import SASTS_DIR, MissingFile

SASTS_ALL = {}
for child in SASTS_DIR.iterdir():
    if child.is_dir():
        if list(child.glob("sast.py")) and child.name != "core":
            sast_name = child.name

            try:
                sast_module = importlib.import_module(
                    f"codesectools.sasts.{sast_name}.sast"
                )

                sast: SAST = getattr(sast_module, f"{sast_name}SAST")
                analysis_result: AnalysisResult = getattr(
                    sast_module, f"{sast_name}AnalysisResult"
                )

                cli_module = importlib.import_module(
                    f"codesectools.sasts.{sast_name}.cli"
                )
                cli: typer.Typer = getattr(cli_module, f"{sast_name}CLI")

                SASTS_ALL[sast_name] = {
                    "sast": sast,
                    "analysis_result": analysis_result,
                    "cli": cli,
                }
            except MissingFile:
                # TODO: Print message
                continue
