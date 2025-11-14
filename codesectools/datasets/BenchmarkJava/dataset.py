"""Defines the BenchmarkJava dataset for evaluating SAST tools on Java code.

This module provides the classes and logic to load the BenchmarkJava dataset, which
consists of Java test files with known vulnerabilities. It clones the source code
from a Git repository and associates test files with expected results from a CSV file.
"""

import csv
import random
from pathlib import Path
from typing import Self

import git

from codesectools.datasets.core.dataset import File, PrebuiltFileDataset
from codesectools.shared.cwe import CWE, CWEs


class TestCode(File):
    """Represents a single test file in the BenchmarkJava dataset.

    Inherits from the base `File` class and adds a `vuln_type` attribute
    specific to this dataset.

    """

    def __init__(
        self,
        filepath: Path,
        content: str | bytes,
        cwes: list[CWE],
        has_vuln: bool,
    ) -> None:
        """Initialize a TestCode instance.

        Args:
            filepath: The path to the file.
            content: The content of the file, as a string or bytes.
            cwes: A list of CWEs associated with the file.
            has_vuln: A boolean indicating if the vulnerability is real or a false positive test case.

        """
        super().__init__(
            filepath=filepath, content=content, cwes=cwes, has_vuln=has_vuln
        )


class BenchmarkJava(PrebuiltFileDataset):
    """Represents the BenchmarkJava dataset.

    This class handles the loading of the dataset, which includes Java test files
    and their corresponding vulnerability information.

    Attributes:
        name (str): The name of the dataset, "BenchmarkJava".
        supported_languages (list[str]): A list of supported programming languages.
        license (str): The license under which the dataset is distributed.
        license_url (str): A URL to the full text of the license.
        build_command (str): The command to build the Java project.
        prebuilt_expected (tuple): A tuple defining the path and glob pattern for expected build artifacts.
        artefacts_arg (str): The argument to specify the location of build artifacts for SAST tools.

    """

    name = "BenchmarkJava"
    supported_languages = ["java"]
    license = "GPL-2.0"
    license_url = "https://github.com/OWASP-Benchmark/BenchmarkJava/blob/master/LICENSE"

    build_command = "mvn clean compile"
    prebuilt_expected = (Path("target/classes/org/owasp/benchmark/testcode"), "*.class")
    artefacts_arg = "."

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

    def download_files(self: Self, test: bool = False) -> None:
        """Download the dataset files from the official Git repository.

        Clones the BenchmarkJava repository and, if in test mode, prunes it to a smaller size.

        Args:
            test: If True, reduce the number of test files for faster testing.

        """
        git.Repo.clone_from(
            "https://github.com/OWASP-Benchmark/BenchmarkJava.git", self.directory
        )

        if test:
            testcodes = list(
                (
                    self.directory / "src/main/java/org/owasp/benchmark/testcode"
                ).iterdir()
            )
            for to_delete_testcode in random.sample(testcodes, k=len(testcodes) - 50):
                to_delete_testcode.unlink()

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
            filepath = testcode_dir / filename
            content = filepath.read_text()
            cwes = [CWEs.from_id(int(row[3]))]
            has_vuln = True if row[2] == "true" else False
            files.append(
                TestCode(
                    filepath.relative_to(self.directory),
                    content,
                    cwes,
                    has_vuln,
                )
            )

        return files
