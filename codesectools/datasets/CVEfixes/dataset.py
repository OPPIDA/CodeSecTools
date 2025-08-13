"""Defines the CVEfixes dataset for evaluating SAST tools on real-world vulnerabilities.

This module provides the classes and logic to load the CVEfixes dataset, which
is composed of Git repositories at commits just before a CVE-related fix.
It reads repository information from a CSV file.
"""

import csv
from typing import Self

from codesectools.datasets.core.dataset import GitRepo, GitRepoDataset
from codesectools.utils import DATASETS_DIR


class CVEfixes(GitRepoDataset):
    """Represents the CVEfixes dataset.

    This class handles loading the dataset of Git repositories linked to specific
    CVEs. It filters repositories based on size.

    Attributes:
        name (str): The name of the dataset, "CVEfixes".
        supported_languages (list[str]): A list of supported languages.
        max_repo_size (int): The maximum size of a repository (in bytes) to be
            included in the analysis.

    """

    name = "CVEfixes"
    supported_languages = ["java"]

    def __init__(self, lang: str) -> None:
        """Initialize the CVEfixes dataset.

        Args:
            lang: The programming language of the dataset to load.

        """
        self.max_repo_size = 100e6
        super().__init__(lang)

    def download_dataset(self: Self) -> None:
        """Prepare the dataset directory and copies the necessary CSV files."""
        if not self.directory.is_dir():
            self.directory.mkdir()
            for dataset_file in (DATASETS_DIR / self.name / "data").glob(
                "CVEfixes_*.csv"
            ):
                (self.directory / dataset_file.name).write_bytes(
                    dataset_file.read_bytes()
                )

    def load_dataset(
        self,
    ) -> list[GitRepo]:
        """Load the CVEfixes dataset from its source CSV file.

        Parses a CSV file containing information about CVEs, repositories,
        commits, and vulnerable files to create a list of `GitRepo` objects.

        Returns:
            A list of `GitRepo` objects representing the dataset, filtered by
            repository size.

        """
        dataset_path = self.directory / f"CVEfixes_{self.lang}.csv"
        repos = []
        with open(dataset_path, newline="", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                name = row["cve_id"]
                url = row["repo_url"]
                commit = eval(row["parents"])[0]
                size = int(row["repo_size"])
                cwe_ids = [
                    int(cwe_id.split("-")[1]) for cwe_id in row["cwe_ids"].split(";")
                ]
                files = row["filenames"].split(";")
                repo = GitRepo(name, url, commit, size, cwe_ids, files)
                if repo.size < self.max_repo_size:
                    repos.append(repo)
        return repos
