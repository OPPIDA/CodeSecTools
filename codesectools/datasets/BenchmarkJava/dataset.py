"""Defines the BenchmarkJava dataset for evaluating SAST tools on Java code.

This module provides the classes and logic to load the BenchmarkJava dataset, which
consists of Java test files with known vulnerabilities. It clones the source code
from a Git repository and associates test files with expected results from a CSV file.
"""

import csv
from typing import Self

import git

from codesectools.datasets.core.dataset import File, FileDataset
from codesectools.shared.cwe import CWE, CWEs


class TestCode(File):
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
        cwes: list[CWE],
        vuln_type: str,
        has_vuln: bool,
    ) -> None:
        """Initialize a TestCode instance.

        Args:
            filename: The name of the file.
            content: The content of the file, as a string or bytes.
            cwes: A list of CWEs associated with the file.
            vuln_type: The type of vulnerability.
            has_vuln: A boolean indicating if the vulnerability is real or a false positive test case.

        """
        super().__init__(
            filename=filename, content=content, cwes=cwes, has_vuln=has_vuln
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
    license = "GPL-2.0"
    license_url = "https://github.com/OWASP-Benchmark/BenchmarkJava/blob/master/LICENSE"

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

    def download_files(self: Self) -> None:
        """Download the dataset files from the official Git repository."""
        repo = git.Repo.clone_from(
            "https://github.com/OWASP-Benchmark/BenchmarkJava.git",
            self.directory,
            depth=1,
            sparse=True,
            filter=["tree:0"],
        )
        repo.git.sparse_checkout(
            "set",
            "--no-cone",
            *[
                "src/main/java/org/owasp/benchmark/testcode/",
                "expectedresults-1.2.csv",
                "LICENSE",
            ],
        )

    def load_dataset(self) -> list[TestCode]:
        """Load the BenchmarkJava dataset from its source files.

        Reads a CSV file for vulnerability metadata and the corresponding Java
        source files from the cloned repository. It creates a `TestCode` object
        for each entry.

        Returns:
            A list of `TestCode` objects representing the dataset.

        """
        files = []
        testcode_dir = (
            self.directory
            / "src"
            / "main"
            / "java"
            / "org"
            / "owasp"
            / "benchmark"
            / "testcode"
        )
        reader = csv.reader((self.directory / "expectedresults-1.2.csv").open())
        next(reader)
        for row in reader:
            filename = f"{row[0]}.java"
            content = (testcode_dir / filename).read_text()
            cwes = [CWEs.from_id(int(row[3]))]
            vuln_type = row[1]
            has_vuln = True if row[2] == "true" else False
            files.append(TestCode(filename, content, cwes, vuln_type, has_vuln))

        return files
