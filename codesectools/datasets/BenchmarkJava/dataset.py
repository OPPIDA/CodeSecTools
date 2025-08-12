"""Defines the BenchmarkJava dataset for evaluating SAST tools on Java code.

This module provides the classes and logic to load the BenchmarkJava dataset, which
consists of Java test files with known vulnerabilities. It reads test files
from a zip archive and associates them with expected results from a CSV file.
"""

import csv
import zipfile
from typing import Self

from codesectools.datasets.core.dataset import File, FileDataset


class TestFile(File):
    """Represents a single test file in the BenchmarkJava dataset.

    Inherits from the base `File` class and adds a `vuln_type` attribute
    specific to this dataset.

    Attributes:
        vuln_type (str): The type of vulnerability present in the file.

    """

    def __init__(
        self,
        filename: str,
        content: str | bytes,
        cwe_ids: list[int],
        vuln_type: str,
        is_real: bool,
    ) -> None:
        """Initialize a TestFile instance.

        Args:
            filename: The name of the file.
            content: The content of the file, as a string or bytes.
            cwe_ids: A list of CWE IDs associated with the file.
            vuln_type: The type of vulnerability.
            is_real: A boolean indicating if the vulnerability is real or a false positive test case.

        """
        super().__init__(
            filename=filename, content=content, cwe_ids=cwe_ids, is_real=is_real
        )

        self.vuln_type = vuln_type


class BenchmarkJava(FileDataset):
    """Represents the BenchmarkJava dataset.

    This class handles the loading of the dataset, which includes Java test files
    and their corresponding vulnerability information.

    Attributes:
        name (str): The name of the dataset, "BenchmarkJava".
        supported_languages (list[str]): A list of supported programming languages.

    """

    name = "BenchmarkJava"
    supported_languages = ["java"]

    def __init__(self, lang: None | str = None) -> None:
        """Initialize the BenchmarkJava dataset.

        Args:
            lang: The programming language of the dataset files.
                Must be one of the supported languages.

        """
        super().__init__(lang)

    def __eq__(self, other: str | Self) -> bool:
        """Compare this dataset with another object for equality.

        Args:
            other: The object to compare with. Can be a string (dataset name)
                   or another BenchmarkJava instance.

        Returns:
            True if the names are equal, False otherwise.

        """
        if isinstance(other, str):
            return self.name == other
        elif isinstance(other, self.__class__):
            return self.name == other.name
        else:
            return False

    def load_dataset(self) -> list[TestFile]:
        """Load the BenchmarkJava dataset from its source files.

        Reads a CSV file for vulnerability metadata and a zip file containing
        the Java source code. It creates a `TestFile` object for each entry.

        Returns:
            A list of `TestFile` objects representing the dataset.

        """
        files = []
        testfiles = zipfile.ZipFile((self.directory / "data" / "tests.zip").open("rb"))
        reader = csv.reader(
            (self.directory / "data" / "expectedresults-1.2.csv").open()
        )
        next(reader)
        for row in reader:
            filename = f"{row[0]}.java"
            content = testfiles.open(filename).read()
            cwe_ids = [int(row[3])]
            vuln_type = row[1]
            is_real = True if row[2] == "true" else False
            files.append(TestFile(filename, content, cwe_ids, vuln_type, is_real))

        return files
