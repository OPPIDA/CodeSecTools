"""Define requirements for SAST tools and their fulfillment status."""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Literal

import typer
from rich import print

from codesectools.utils import USER_CACHE_DIR, USER_CONFIG_DIR

if TYPE_CHECKING:
    from pathlib import Path


class SASTRequirement(ABC):
    """Represent a single requirement for a SAST tool to be functional."""

    def __init__(
        self,
        name: str,
        depends_on: list[SASTRequirement] | None = None,
        instruction: str | None = None,
        url: str | None = None,
        doc: bool = False,
    ) -> None:
        """Initialize a SASTRequirement instance.

        Args:
            name: The name of the requirement.
            depends_on: A list of other requirements that must be fulfilled first.
            instruction: A short instruction on how to download the requirement.
            url: A URL for more detailed instructions.
            doc: A flag indicating if the instruction is available in the documentation.

        """
        self.name = name
        self.depends_on = depends_on
        self.instruction = instruction
        self.url = url
        self.doc = doc

    @abstractmethod
    def is_fulfilled(self, **kwargs: Any) -> bool:
        """Check if the requirement is met."""
        pass

    def dependencies_fulfilled(self) -> bool:
        """Check if all dependencies for this requirement are fulfilled."""
        if not self.depends_on:
            return True
        return all(dependency.is_fulfilled() for dependency in self.depends_on)

    def __repr__(self) -> str:
        """Return a developer-friendly string representation of the requirement."""
        return f"{self.__class__.__name__}({self.name})"


class DownloadableRequirement(SASTRequirement):
    """Represent a SAST requirement that can be downloaded automatically."""

    def __init__(
        self,
        name: str,
        depends_on: list[SASTRequirement] | None = None,
        instruction: str | None = None,
        url: str | None = None,
        doc: bool = False,
    ) -> None:
        """Initialize a DownloadableRequirement instance.

        Sets a standard instruction message on how to download the requirement using the CLI.

        Args:
            name: The name of the requirement.
            depends_on: A list of other requirements that must be fulfilled first.
            instruction: A short instruction on how to download the requirement.
            url: A URL for more detailed instructions.
            doc: A flag indicating if the instruction is available in the documentation.

        """
        instruction = f"cstools download {name}"
        super().__init__(
            name=name, depends_on=depends_on, instruction=instruction, url=url, doc=doc
        )

    @abstractmethod
    def download(self, **kwargs: Any) -> None:
        """Download the requirement."""
        pass


class Config(SASTRequirement):
    """Represent a configuration file requirement for a SAST tool."""

    def __init__(
        self,
        name: str,
        sast_name: str,
        depends_on: list[SASTRequirement] | None = None,
        instruction: str | None = None,
        url: str | None = None,
        doc: bool = False,
    ) -> None:
        """Initialize a Config instance.

        Args:
            name: The name of the requirement.
            sast_name: The name of the SAST tool this config belongs to.
            depends_on: A list of other requirements that must be fulfilled first.
            instruction: A short instruction on how to download the requirement.
            url: A URL for more detailed instructions.
            doc: A flag indicating if the instruction is available in the documentation.

        """
        self.sast_name = sast_name
        super().__init__(
            name=name, depends_on=depends_on, instruction=instruction, url=url, doc=doc
        )

    def is_fulfilled(self, **kwargs: Any) -> bool:
        """Check if the configuration file exists for the given SAST tool."""
        return (USER_CONFIG_DIR / self.sast_name / self.name).is_file()


class Binary(SASTRequirement):
    """Represent a binary executable requirement for a SAST tool."""

    def __init__(
        self,
        name: str,
        depends_on: list[SASTRequirement] | None = None,
        instruction: str | None = None,
        url: str | None = None,
        doc: bool = False,
    ) -> None:
        """Initialize a Binary instance.

        Args:
            name: The name of the requirement.
            depends_on: A list of other requirements that must be fulfilled first.
            instruction: A short instruction on how to download the requirement.
            url: A URL for more detailed instructions.
            doc: A flag indicating if the instruction is available in the documentation.

        """
        super().__init__(
            name=name, depends_on=depends_on, instruction=instruction, url=url, doc=doc
        )

    def is_fulfilled(self, **kwargs: Any) -> bool:
        """Check if the binary is available in the system's PATH."""
        return bool(shutil.which(self.name))


class GitRepo(DownloadableRequirement):
    """Represent a Git repository requirement that can be downloaded."""

    def __init__(
        self,
        name: str,
        repo_url: str,
        license: str,
        license_url: str,
        depends_on: list[SASTRequirement] | None = None,
        instruction: str | None = None,
        url: str | None = None,
        doc: bool = False,
    ) -> None:
        """Initialize a GitRepo requirement instance.

        Args:
            name: The name of the requirement.
            repo_url: The URL of the Git repository to clone.
            license: The license of the repository.
            license_url: A URL for the repository's license.
            depends_on: A list of other requirements that must be fulfilled first.
            instruction: A short instruction on how to download the requirement.
            url: A URL for more detailed instructions.
            doc: A flag indicating if the instruction is available in the documentation.

        """
        super().__init__(
            name=name, depends_on=depends_on, instruction=instruction, url=url, doc=doc
        )
        self.repo_url = repo_url
        self.license = license
        self.license_url = license_url
        self.directory = USER_CACHE_DIR / self.name

    def is_fulfilled(self, **kwargs: Any) -> bool:
        """Check if the Git repository has been cloned."""
        return (self.directory / ".complete").is_file()

    def download(self, **kwargs: Any) -> None:
        """Prompt for license agreement and clone the Git repository."""
        from git import Repo
        from rich.panel import Panel
        from rich.progress import Progress

        panel = Panel(
            f"""Repository:\t[b]{self.name}[/b]
Repository URL:\t[u]{self.repo_url.rstrip(".git")}[/u]
License:\t[b]{self.license}[/b]
License URL:\t[u]{self.license_url}[/u]

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


class File(DownloadableRequirement):
    """Represent a file requirement that can be downloaded."""

    def __init__(
        self,
        name: str,
        parent_dir: Path,
        file_url: str,
        license: str,
        license_url: str,
        depends_on: list[SASTRequirement] | None = None,
        instruction: str | None = None,
        url: str | None = None,
        doc: bool = False,
    ) -> None:
        """Initialize a File requirement instance.

        Args:
            name: The name of the requirement.
            parent_dir: The directory where the file should be saved.
            file_url: The URL to download the file from.
            license: The license of the file.
            license_url: A URL for the file's license.
            depends_on: A list of other requirements that must be fulfilled first.
            instruction: A short instruction on how to download the requirement.
            url: A URL for more detailed instructions.
            doc: A flag indicating if the instruction is available in the documentation.

        """
        super().__init__(
            name=name, depends_on=depends_on, instruction=instruction, url=url, doc=doc
        )
        self.parent_dir = parent_dir
        self.file_url = file_url
        self.license = license
        self.license_url = license_url

    def is_fulfilled(self, **kwargs: Any) -> bool:
        """Check if the file has been downloaded."""
        return bool(list(self.parent_dir.glob(self.name)))

    def download(self, **kwargs: Any) -> None:
        """Prompt for license agreement and download the file."""
        import requests
        from rich.panel import Panel
        from rich.progress import Progress

        panel = Panel(
            f"""File:\t\t[b]{self.name}[/b]
Download URL:\t[u]{self.file_url}[/u]
License:\t[b]{self.license}[/b]
License URL:\t[u]{self.license_url}[/u]

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
            progress.add_task(f"Downloading file [b]{self.name}[/b]...", total=None)
            response = requests.get(self.file_url)
            (self.parent_dir / self.name).write_bytes(response.content)

        print(f"[b]{self.name}[/b] has been downloaded at {self.parent_dir}.")


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
