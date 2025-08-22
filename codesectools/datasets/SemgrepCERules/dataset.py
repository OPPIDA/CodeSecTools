"""Defines the SemgrepCERules dataset for evaluating SAST tools.

This module provides classes and logic to load the SemgrepCERules dataset, which is
derived from the test cases within Semgrep's community rule definitions. It extracts
code snippets, associated CWEs, and other metadata from Semgrep's YAML rule files.
"""

import re
from typing import Self

import git
import yaml

from codesectools.datasets.core.dataset import File, FileDataset
from codesectools.shared.cwe import CWE, CWEs


class TestFile(File):
    """Represents a single test file derived from a Semgrep rule's test case.

    Inherits from the base `File` class. The `is_real` attribute is always
    True for this dataset as test cases represent true positives.
    """

    def __init__(
        self,
        filename: str,
        content: str | bytes,
        cwes: list[CWE],
        is_real: bool = True,
    ) -> None:
        """Initialize a TestFile instance.

        Args:
            filename: The name of the file.
            content: The content of the file, as a string or bytes.
            cwes: A list of CWEs associated with the file.
            is_real: A boolean indicating if the vulnerability is real.
                     Defaults to True.

        """
        super().__init__(filename=filename, content=content, cwes=cwes, is_real=True)


class SemgrepCERules(FileDataset):
    """Represents the SemgrepCERules dataset.

    This class handles the loading of the dataset by parsing YAML files
    containing Semgrep community rules and their associated test cases.

    Attributes:
        name (str): The name of the dataset, "SemgrepCERules".
        supported_languages (list[str]): A list of supported programming languages.

    """

    name = "SemgrepCERules"
    supported_languages = ["java"]

    def __init__(self, lang: str) -> None:
        """Initialize the SemgrepCERules dataset.

        Args:
            lang: The programming language of the dataset files to load.

        """
        super().__init__(lang)

    def download_dataset(self: Self) -> None:
        """Download the dataset by sparsely cloning the semgrep-rules Git repository."""
        repo = git.Repo.clone_from(
            "https://github.com/semgrep/semgrep-rules.git",
            self.directory,
            depth=1,
            sparse=True,
            filter=["tree:0"],
        )
        repo.git.sparse_checkout(
            "set",
            "--no-cone",
            *self.supported_languages,
        )

    def load_dataset(self) -> list[TestFile]:
        """Load the SemgrepCERules dataset from the rule repository.

        Parses the YAML rule files, iterates through the rules, extracts
        relevant test cases for the specified language, and creates
        `TestFile` objects.

        Returns:
            A list of `TestFile` objects representing the dataset.

        """
        LANG_RULES = self.directory / self.lang
        rule_files = list(LANG_RULES.rglob("*.yml")) + list(LANG_RULES.rglob("*.yaml"))

        files = []
        for rule_file in rule_files:
            if "." in rule_file.stem:
                continue

            rule = yaml.load(rule_file.open(), Loader=yaml.Loader)["rules"][0]

            cwes = rule["metadata"].get("cwe")
            if not cwes:
                continue
            if isinstance(cwes, str):
                cwes = [cwes]

            cwes = []
            for cwe in cwes:
                if match := re.search(r"[CWE|cwe]-(\d+)", cwe):
                    cwes.append(CWEs().from_id(int(match.group(1))))

            if self.lang in rule["languages"]:
                test_file = next(LANG_RULES.rglob(f"{rule_file.stem}*"))
                files.append(TestFile(test_file.name, test_file.read_bytes(), cwes))
        return files
