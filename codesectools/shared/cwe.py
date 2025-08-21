"""Handle Common Weakness Enumeration (CWE) data.

This module downloads the CWE list from cwe.mitre.org if not already cached,
and provides classes to access and manage CWE data.
"""

import csv
import io
import zipfile

import requests

from codesectools.utils import USER_CACHE_DIR


class CWE:
    """Represent a single Common Weakness Enumeration."""

    def __init__(self, id: int, name: str, description: str) -> None:
        """Initialize a CWE instance.

        Args:
            id: The CWE identifier.
            name: The name of the weakness.
            description: A description of the weakness.

        """
        self.id = id
        self.name = name
        self.description = description


class CWEs:
    """Manage the collection of CWEs."""

    def __init__(self) -> None:
        """Initialize the CWEs collection.

        Download the CWE data from cwe.mitre.org if it's not present in the user cache.
        """
        self.file = USER_CACHE_DIR / "699.csv"
        if not self.file.is_file():
            zip_file = io.BytesIO(
                requests.get("https://cwe.mitre.org/data/csv/699.csv.zip").content
            )
            with zipfile.ZipFile(zip_file, "r") as zip_ref:
                zip_ref.extract("699.csv", USER_CACHE_DIR)

        self.cwes = self.load()

    def load(self) -> list[CWE]:
        """Load CWE data from the CSV file.

        Returns:
            A list of CWE objects.

        """
        cwes = []
        reader = csv.DictReader(self.file.open(encoding="utf-8"))
        for cwe_dict in reader:
            cwes.append(
                CWE(
                    id=int(cwe_dict["CWE-ID"]),
                    name=cwe_dict["Name"],
                    description=cwe_dict["Description"],
                )
            )
        return cwes

    def from_id(self, id: int) -> CWE | None:
        """Get a CWE by its identifier.

        Args:
            id: The integer ID of the CWE to find.

        Returns:
            The CWE object if found, otherwise None.

        """
        for cwe in self.cwes:
            if cwe.id == id:
                return cwe
        return None
