"""Define requirements for SAST tools and their fulfillment status."""

import shutil
from abc import ABC, abstractmethod
from typing import Literal

import typer
from git import Repo
from rich import print
from rich.panel import Panel
from rich.progress import Progress

from codesectools.utils import USER_CACHE_DIR, USER_CONFIG_DIR


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
            instruction: A short instruction on how to download the requirement.
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


class DownloadableRequirement(SASTRequirement):
    """Represent a SAST requirement that can be downloaded automatically."""

    def __init__(
        self,
        name: str,
        instruction: str | None = None,
        url: str | None = None,
        doc: bool = False,
    ) -> None:
        """Initialize a DownloadableRequirement instance.

        Sets a standard instruction message on how to download the requirement using the CLI.

        Args:
            name: The name of the requirement.
            instruction: A short instruction on how to download the requirement.
            url: A URL for more detailed instructions.
            doc: A flag indicating if the instruction is available in the documentaton.

        """
        instruction = f"cstools download {name}"
        super().__init__(name, instruction, url, doc)

    @abstractmethod
    def download(self, **kwargs: dict) -> None:
        """Download the requirement."""
        pass


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
            instruction: A short instruction on how to download the requirement.
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
            instruction: A short instruction on how to download the requirement.
            url: A URL for more detailed instructions.
            doc: A flag indicating if this is a documentation-only requirement.

        """
        super().__init__(name, instruction, url, doc)

    def is_fulfilled(self, **kwargs: dict) -> bool:
        """Check if the binary is available in the system's PATH."""
        return bool(shutil.which(self.name))


class GitRepo(DownloadableRequirement):
    """Represent a Git repository requirement that can be downloaded."""

    def __init__(
        self,
        name: str,
        repo_url: str,
        instruction: str | None = None,
        url: str | None = None,
        doc: bool = False,
    ) -> None:
        """Initialize a GitRepo requirement instance.

        Args:
            name: The name of the requirement.
            repo_url: The URL of the Git repository to clone.
            instruction: A short instruction on how to download the requirement.
            url: A URL for more detailed instructions.
            doc: A flag indicating if the instruction is available in the documentaton.

        """
        super().__init__(name, instruction, url, doc)
        self.repo_url = repo_url
        self.directory = USER_CACHE_DIR / self.name

    def is_fulfilled(self, **kwargs: dict) -> bool:
        """Check if the Git repository has been cloned."""
        return (self.directory / ".complete").is_file()

    def download(self, **kwargs: dict) -> None:
        """Prompt for license agreement and clone the Git repository."""
        panel = Panel(
            f"""Git repository:\t[b]{self.name}[/b]
Repository URL:\t[u]{self.repo_url}[/u]

Please review the license of the repository at the URL above.
By proceeding, you agree to abide by its terms.""",
            title="[b]License Agreement[/b]",
        )
        print(panel)

        agreed = typer.confirm("Do you accept the license terms and wish to proceed?")
        if not agreed:
            print("[red]License agreement declined. Download aborted.[/red]")
            raise typer.Exit(code=1)

        with Progress() as progress:
            progress.add_task(f"Cloning repository [b]{self.name}[/b]...", total=None)
            Repo.clone_from(
                self.repo_url,
                self.directory,
                depth=1,
            )
        (self.directory / ".complete").write_bytes(b"\x42")
        print(f"[b]{self.name}[/b] has been downloaded at {self.directory}.")


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
        self.full = full_reqs
        self.partial = partial_reqs
        self.all = full_reqs + partial_reqs

    def get_status(self) -> Literal["full"] | Literal["partial"] | Literal["none"]:
        """Determine the operational status (full, partial, none) based on fulfilled requirements."""
        # full: can run sast analysis and result parsing
        # partial: can run result parsing
        # none: nothing
        status = "none"
        if all(req.is_fulfilled(sast_name=self.name) for req in self.partial):
            status = "partial"
            if all(req.is_fulfilled(sast_name=self.name) for req in self.full):
                status = "full"
        return status

    def get_missing(self) -> list[SASTRequirement]:
        """Get a list of all unfulfilled requirements."""
        missing = []
        for req in self.all:
            if not req.is_fulfilled(sast_name=self.name):
                missing.append(req)
        return missing
