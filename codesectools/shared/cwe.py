"""Handle Common Weakness Enumeration (CWE) data.

This module downloads the CWE list from cwe.mitre.org if not already cached,
and provides classes to access and manage CWE data.
"""

import csv
import io
import re
import zipfile
from typing import Self

from codesectools.utils import USER_CACHE_DIR


class CWE:
    """Represent a single Common Weakness Enumeration.

    Attributes:
        id (int): The CWE identifier.
        name (str): The name of the weakness.
        description (str): A description of the weakness.
        parent (CWE | None): The parent CWE weakness, if any.
        children (set[CWE]): A set of child CWE weaknesses.

    """

    def __init__(
        self,
        id: int,
        name: str,
        description: str,
        parent: Self | None = None,
        children: set[Self] | None = None,
    ) -> None:
        """Initialize a CWE instance.

        Args:
            id: The CWE identifier.
            name: The name of the weakness.
            description: A description of the weakness.
            parent: The parent CWE weakness, if any.
            children: A set of child CWE weaknesses, if any.

        """
        if children is None:
            children = set()
        self.id = id
        if r := re.search(r"\('(.*)'\)", name):
            self.name = r.group(1)
            self.full_name = name
        else:
            self.name = self.full_name = name

        self.description = description
        self.parent = parent
        self.children = children or set()

    def __eq__(self, other: object) -> bool:
        """Compare this CWE with another object for equality.

        Args:
            other: The object to compare with. Can be another CWE instance
                   or an integer representing the CWE ID.

        Returns:
            True if the IDs are equal, False otherwise.

        """
        if isinstance(other, self.__class__):
            return self.id == other.id
        elif isinstance(other, int):
            return self.id == other
        else:
            return False

    def __hash__(self) -> int:
        """Return the hash of the CWE instance, based on its ID."""
        return hash(self.id)

    def __repr__(self) -> str:
        """Return a developer-friendly string representation of the CWE.

        Returns:
            A string showing the class name and CWE ID.

        """
        return f"{self.__class__.__name__}(id={self.id})"

    def extend(self, distance: int = 1) -> set[Self]:
        """Retrieve the set of related CWEs within a specified distance in the hierarchy.

        Recursively finds parent and child CWEs up to the given distance level.
        Includes the current CWE in the returned set.

        Args:
            distance: The number of levels to traverse up (parents) and down (children).
                Defaults to 1.

        Returns:
            A set of CWE objects including the self and related weaknesses.

        """
        cwes = set([self])
        for _ in range(distance):
            new_cwes = cwes.copy()
            for cwe in cwes:
                if cwe.parent:
                    new_cwes.add(cwe.parent)
                for child in cwe.children:
                    new_cwes.add(child)
            cwes = new_cwes.copy()
        return cwes


class CWEsCollection:
    """Manage the collection of all CWEs.

    Downloads and loads the official CWE list from a CSV file.

    Attributes:
        cwes_data (dict): A mapping of CWE categories to their CSV filenames.
        directory (Path): The path to the cached CWE data directory.
        cwes (list[CWE]): A list of all loaded CWE objects.

    """

    def __init__(self) -> None:
        """Initialize the CWEs collection.

        Download the CWE data from cwe.mitre.org if it's not present in the user cache.
        """
        self.cwes_data = {
            "Software Development": "699.csv",
            "Hardware Design": "1194.csv",
            "Research Concepts": "1000.csv",
        }
        self.directory = USER_CACHE_DIR / "cwe"
        self.NOCWE = CWE(id=-1, name="	Missing or invalid CWE", description="None")
        self._cwes = None

        if not self.directory.is_dir():
            self.download()

    @property
    def cwes(self) -> dict[int, CWE]:
        """Get the list of all CWEs, loading them if necessary."""
        if not self._cwes:
            self._cwes = self.load()

        return self._cwes

    def download(self) -> None:
        """Download CWE data from the official MITRE website."""
        import requests
        from rich.progress import Progress

        with Progress() as progress:
            task = progress.add_task(
                "[red]Downloading CWEs from [b]cwe.mitre.org[/b]...", total=100
            )
            for filename in self.cwes_data.values():
                if not (self.directory / filename).is_file():
                    zip_file = io.BytesIO(
                        requests.get(
                            f"https://cwe.mitre.org/data/csv/{filename}.zip"
                        ).content
                    )
                    with zipfile.ZipFile(zip_file, "r") as zip_ref:
                        zip_ref.extract(filename, self.directory)
                progress.update(task, advance=25)

            terms_file = self.directory / "termsofuse.html"
            terms_file.write_bytes(
                requests.get("https://cwe.mitre.org/about/termsofuse.html").content
            )
            progress.update(task, advance=25)

    def load(self) -> dict[int, CWE]:
        """Load and parse CWE data from cached CSV files.

        Reads the CSV files defined in `cwes_data`, instantiates `CWE` objects,
        and establishes parent-child relationships based on the "Related Weaknesses" field.

        Returns:
            A dictionary mapping CWE IDs (int) to `CWE` objects.

        """
        cwes = {}
        cwes_parent = {}
        cwes_children = {}
        for filename in self.cwes_data.values():
            reader = csv.DictReader((self.directory / filename).open(encoding="utf-8"))
            for cwe_dict in reader:
                cwe_id = int(cwe_dict["CWE-ID"])

                cwes[cwe_id] = CWE(
                    id=cwe_id,
                    name=cwe_dict["Name"],
                    description=cwe_dict["Description"],
                )

                for related in cwe_dict["Related Weaknesses"].split("::"):
                    if m := re.search(r"NATURE:ChildOf:CWE ID:(\d+):", related):
                        parent_id = int(m.group(1))

                        cwes_parent[cwe_id] = parent_id

                        if cwes_children.get(parent_id):
                            cwes_children[parent_id].add(cwe_id)
                        else:
                            cwes_children[parent_id] = {cwe_id}

                        break

        for cwe_id, cwe in cwes.items():
            if p_id := cwes_parent.get(cwe_id):
                cwe.parent = cwes.get(p_id, None)
            for c_id in cwes_children.get(cwe_id, []):
                if child_cwe := cwes.get(c_id):
                    cwe.children.add(child_cwe)

        return cwes

    def from_string(self, cwe_string: str) -> CWE:
        """Get a CWE from a string like 'CWE-79'.

        Args:
            cwe_string: The string representation of the CWE ID.

        Returns:
            The corresponding CWE object, or a default 'Invalid CWE' object if the string is malformed.

        """
        if match := re.search(r"[CWE|cwe]-(\d+)", cwe_string):
            return self.from_id(int(match.group(1)))
        else:
            return self.NOCWE

    def from_id(self, cwe_id: int) -> CWE:
        """Get a CWE by its identifier.

        Args:
            cwe_id: The integer ID of the CWE to find.

        Returns:
            The CWE object if found, otherwise a default CWE object with ID -1.

        """
        return self.cwes.get(cwe_id, self.NOCWE)


CWEs = CWEsCollection()
