"""Defines the SemgrepTest dataset for evaluating SAST tools.

This module provides classes and logic to load the SemgrepTest dataset, which is
derived from the test cases within Semgrep's own rule definitions. It extracts
code snippets, associated CWEs, and other metadata from a JSON file of
Semgrep rules.
"""

import base64
import json
import re

from codesectools.datasets.core.dataset import File, FileDataset


class TestFile(File):
    """Represents a single test file derived from a Semgrep rule's test case.

    Inherits from the base `File` class. The `is_real` attribute is always
    True for this dataset as test cases represent true positives.
    """

    def __init__(
        self,
        filename: str,
        content: str | bytes,
        cwe_ids: list[int],
        is_real: bool = True,
    ) -> None:
        """Initialize a TestFile instance.

        Args:
            filename: The name of the file.
            content: The content of the file, as a string or bytes.
            cwe_ids: A list of CWE IDs associated with the file.
            is_real: A boolean indicating if the vulnerability is real.
                     Defaults to True.

        """
        super().__init__(
            filename=filename, content=content, cwe_ids=cwe_ids, is_real=True
        )


class SemgrepTest(FileDataset):
    """Represents the SemgrepTest dataset.

    This class handles the loading of the dataset by parsing a large JSON file
    containing Semgrep rules and their associated test cases.

    Attributes:
        name (str): The name of the dataset, "SemgrepTest".
        supported_languages (list[str]): A list of supported programming languages.

    """

    name = "SemgrepTest"
    supported_languages = ["java"]

    def __init__(self, lang: str) -> None:
        """Initialize the SemgrepTest dataset.

        Args:
            lang: The programming language of the dataset files to load.

        """
        super().__init__(lang)

    def load_dataset(self) -> list[TestFile]:
        """Load the SemgrepTest dataset from a base64-encoded JSON file.

        Decodes and parses the JSON file, iterates through Semgrep rules,
        extracts relevant test cases for the specified language, and creates
        `TestFile` objects.

        Returns:
            A list of `TestFile` objects representing the dataset.

        """
        SEMGREP_RULES = json.loads(
            base64.b64decode(
                (self.directory / "data" / "Semgrep_all.json.b64").read_bytes()
            )
        )

        files = []
        for rule in SEMGREP_RULES:
            cwes = rule["definition"]["rules"][0]["metadata"].get("cwe")
            if not cwes:
                continue
            if isinstance(cwes, str):
                cwes = [cwes]

            cwe_ids = []
            for cwe in cwes:
                if match := re.search(r"[CWE|cwe]-(\d+)", cwe):
                    cwe_ids.append(int(match.group(1)))

            languages = rule["definition"]["rules"][0]["languages"]
            if self.lang not in languages:
                continue

            if rule.get("test_cases"):
                for test in rule["test_cases"]:
                    if self.lang == test["language"]:
                        files.append(
                            TestFile(test["filename"], test["target"], cwe_ids)
                        )

        return files
