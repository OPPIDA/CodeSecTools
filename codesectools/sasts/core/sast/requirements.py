"""Define requirements for SAST tools and their fulfillment status."""

import shutil
from abc import ABC, abstractmethod
from typing import Literal

from codesectools.datasets import DATASETS_ALL
from codesectools.utils import (
    USER_CONFIG_DIR,
)


class SASTRequirement(ABC):
    """Represent a single requirement for a SAST tool to be functional."""

    def __init__(
        self,
        name: str,
        instruction: str | None = None,
        url: str | None = None,
        doc: bool = False,
    ) -> None:
        """Initialize a SASTRequirement instance.

        Args:
            name: The name of the requirement.
            instruction: A short instruction on how to fulfill the requirement.
            url: A URL for more detailed instructions.
            doc: A flag indicating if the instruction is available in the documentaton.

        """
        self.name = name
        self.instruction = instruction
        self.url = url
        self.doc = doc

    @abstractmethod
    def is_fulfilled(self, **kwargs: dict) -> bool:
        """Check if the requirement is met."""
        pass

    def __repr__(self) -> str:
        """Return a developer-friendly string representation of the requirement."""
        return f"{self.__class__.__name__}({self.name})"


class Config(SASTRequirement):
    """Represent a configuration file requirement for a SAST tool."""

    def __init__(
        self,
        name: str,
        instruction: str | None = None,
        url: str | None = None,
        doc: bool = False,
    ) -> None:
        """Initialize a Config instance.

        Args:
            name: The name of the requirement.
            instruction: A short instruction on how to fulfill the requirement.
            url: A URL for more detailed instructions.
            doc: A flag indicating if this is a documentation-only requirement.

        """
        super().__init__(name, instruction, url, doc)

    def is_fulfilled(self, sast_name: str) -> bool:
        """Check if the configuration file exists for the given SAST tool."""
        return (USER_CONFIG_DIR / sast_name / self.name).is_file()


class Binary(SASTRequirement):
    """Represent a binary executable requirement for a SAST tool."""

    def __init__(
        self,
        name: str,
        instruction: str | None = None,
        url: str | None = None,
        doc: bool = False,
    ) -> None:
        """Initialize a Binary instance.

        Args:
            name: The name of the requirement.
            instruction: A short instruction on how to fulfill the requirement.
            url: A URL for more detailed instructions.
            doc: A flag indicating if this is a documentation-only requirement.

        """
        super().__init__(name, instruction, url, doc)

    def is_fulfilled(self, **kwargs: dict) -> bool:
        """Check if the binary is available in the system's PATH."""
        return bool(shutil.which(self.name))


class DatasetCache(SASTRequirement):
    """Represent a dataset cache requirement for a SAST tool."""

    def __init__(
        self,
        name: str,
        instruction: str | None = None,
        url: str | None = None,
        doc: bool = False,
    ) -> None:
        """Initialize a DatasetCache instance.

        Args:
            name: The name of the requirement.
            instruction: A short instruction on how to fulfill the requirement.
            url: A URL for more detailed instructions.
            doc: A flag indicating if this is a documentation-only requirement.

        """
        instruction = f"cstools dataset download {name}"
        super().__init__(name, instruction, url, doc)

    def is_fulfilled(self, **kwargs: dict) -> bool:
        """Check if the dataset is cached locally."""
        return DATASETS_ALL[self.name].is_cached()


class SASTRequirements:
    """Manage the requirements for a SAST tool and determine its operational status."""

    def __init__(
        self, full_reqs: list[SASTRequirement], partial_reqs: list[SASTRequirement]
    ) -> None:
        """Initialize a SASTRequirements instance.

        Args:
            full_reqs: A list of requirements for full functionality.
            partial_reqs: A list of requirements for partial functionality.

        """
        self.name = None
        self.full_reqs = full_reqs
        self.partial_reqs = partial_reqs

    def get_status(self) -> Literal["full"] | Literal["partial"] | Literal["none"]:
        """Determine the operational status (full, partial, none) based on fulfilled requirements."""
        # full: can run sast analysis and result parsing
        # partial: can run result parsing
        # none: nothing
        status = "none"
        if all(req.is_fulfilled(sast_name=self.name) for req in self.partial_reqs):
            status = "partial"
            if all(req.is_fulfilled(sast_name=self.name) for req in self.full_reqs):
                status = "full"
        return status

    def get_missing(self) -> list[SASTRequirement]:
        """Get a list of all unfulfilled requirements."""
        missing = []
        for req in self.full_reqs + self.partial_reqs:
            if not req.is_fulfilled(sast_name=self.name):
                missing.append(req)
        return missing
