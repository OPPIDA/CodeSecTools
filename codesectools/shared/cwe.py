"""Handle Common Weakness Enumeration (CWE) data.

This module downloads the CWE list from cwe.mitre.org if not already cached,
and provides classes to access and manage CWE data.
"""

import csv
import io
import re
import zipfile
from typing import Self

import requests

from codesectools.utils import USER_CACHE_DIR


class CWE:
    """Represent a single Common Weakness Enumeration.

    Attributes:
        id (int): The CWE identifier.
        name (str): The name of the weakness.
        description (str): A description of the weakness.

    """

    def __init__(self, id: int, name: str, description: str) -> None:
        """Initialize a CWE instance.

        Args:
            id: The CWE identifier.
            name: The name of the weakness.
            description: A description of the weakness.

        """
        self.id = id
        if r := re.search(r"\('(.*)'\)", name):
            self.name = r.group(1)
            self.full_name = name
        else:
            self.name = self.full_name = name

        self.description = description

    def __eq__(self, other: Self | int) -> bool:
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


class CWEsCollection:
    """Manage the collection of all CWEs.

    Downloads and loads the official CWE list from a CSV file.

    Attributes:
        file (Path): The path to the cached CWE CSV file.
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
        for filename in self.cwes_data.values():
            if not (USER_CACHE_DIR / filename).is_file():
                zip_file = io.BytesIO(
                    requests.get(
                        f"https://cwe.mitre.org/data/csv/{filename}.zip"
                    ).content
                )
                with zipfile.ZipFile(zip_file, "r") as zip_ref:
                    zip_ref.extract(filename, USER_CACHE_DIR)

        self.cwes = self.load()

    def load(self) -> list[CWE]:
        """Load CWE data from the CSV file.

        Returns:
            A list of CWE objects.

        """
        cwes = []
        for filename in self.cwes_data.values():
            reader = csv.DictReader((USER_CACHE_DIR / filename).open(encoding="utf-8"))
            for cwe_dict in reader:
                cwes.append(
                    CWE(
                        id=int(cwe_dict["CWE-ID"]),
                        name=cwe_dict["Name"],
                        description=cwe_dict["Description"],
                    )
                )
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
            return CWE(id=-1, name="Invalid CWE", description="None")

    def from_id(self, cwe_id: int) -> CWE:
        """Get a CWE by its identifier.

        Args:
            cwe_id: The integer ID of the CWE to find.

        Returns:
            The CWE object if found, otherwise a default CWE object with ID -1.

        """
        try:
            return self.cwes[self.cwes.index(cwe_id)]
        except ValueError:
            return CWE(id=-1, name="Invalid CWE", description="None")


CWEs = CWEsCollection()
