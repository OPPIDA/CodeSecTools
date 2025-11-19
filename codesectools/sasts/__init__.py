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

from codesectools.sasts.core.cli import CLIFactory
from codesectools.sasts.core.sast import SAST, AnalysisResult
from codesectools.sasts.core.sast.properties import SASTProperties
from codesectools.sasts.core.sast.requirements import SASTRequirement
from codesectools.utils import SASTS_DIR


class LazySASTLoader:
    """Lazily load SAST tool components to avoid premature imports."""

    def __init__(self, name: str) -> None:
        """Initialize the lazy loader.

        Args:
            name: The name of the SAST tool to load.

        """
        self.name = name
        self.loaded = False

    def _load(self) -> None:
        """Import the SAST modules and classes on first access."""
        if not self.loaded:
            sast_module = importlib.import_module(
                f"codesectools.sasts.tools.{self.name}.sast"
            )

            self.sast: SAST = getattr(sast_module, f"{self.name}SAST")
            self.sast_instance: SAST = self.sast()
            self.analysis_result: AnalysisResult = getattr(
                sast_module, f"{self.name}AnalysisResult"
            )

            self.cli_module = importlib.import_module(
                f"codesectools.sasts.tools.{self.name}.cli"
            )
            self.cli_factory: CLIFactory = getattr(
                self.cli_module, f"{self.name}CLIFactory"
            )

            self._data = {
                "status": self.sast_instance.status,
                "missing": self.sast_instance.missing,
                "properties": self.sast_instance.properties,
                "sast": self.sast,
                "analysis_result": self.analysis_result,
                "cli_factory": self.cli_factory,
            }

            self.loaded = True

    def __getitem__(
        self, name: str
    ) -> (
        str
        | list[SASTRequirement]
        | SASTProperties
        | SAST
        | AnalysisResult
        | CLIFactory
    ):
        """Provide dictionary-like access to the loaded SAST components."""
        self._load()
        return self._data[name]

    def __setitem__(
        self,
        name: str,
        value: str
        | list[SASTRequirement]
        | SASTProperties
        | SAST
        | AnalysisResult
        | CLIFactory,
    ) -> None:
        """Provide dictionary-like write access to the loaded SAST components."""
        self._load()
        self._data[name] = value


SASTS_ALL = {}
for child in (SASTS_DIR / "tools").iterdir():
    if child.is_dir():
        sast_name = child.name
        SASTS_ALL[sast_name] = LazySASTLoader(sast_name)

SASTS_ALL = dict(sorted(SASTS_ALL.items()))
