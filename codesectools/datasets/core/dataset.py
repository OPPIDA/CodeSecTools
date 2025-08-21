"""Defines the core abstract classes and data structures for datasets.

This module provides the foundational components for creating and managing
datasets used for benchmarking SAST tools. It includes abstract base classes
for different types of datasets (e.g., file-based, Git repository-based)
and data classes to hold benchmark results.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

import git
import humanize

from codesectools.utils import USER_CACHE_DIR

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Self

    from codesectools.sasts.core.parser import AnalysisResult, Defect


class Dataset(ABC):
    """Abstract base class for all datasets.

    Defines the common interface that all dataset types must implement.

    Attributes:
        name (str): The name of the dataset.
        supported_languages (list[str]): A list of programming languages supported
            by the dataset.

    """

    name: str
    supported_languages: list[str]

    def __init__(self, lang: str) -> None:
        """Initialize the Dataset instance.

        Set up paths, validate the language, and trigger the download and
        loading process for the dataset.

        Args:
            lang: The programming language of the dataset to load. Must be one
                of the supported languages for the dataset class.

        """
        self.directory = USER_CACHE_DIR / self.name
        self.lang = lang
        self.full_name = f"{self.name}_{self.lang}"
        assert self.full_name in self.list_dataset()

        if not self.is_cached():
            self.download_dataset()
            (self.directory / ".complete").write_bytes(b"\x42")

        self.files: list[File] = self.load_dataset()

    @classmethod
    def is_cached(cls) -> bool:
        """Check if the dataset has been downloaded and is cached locally.

        Returns:
            True if the dataset is cached, False otherwise.

        """
        is_complete = USER_CACHE_DIR / cls.name / ".complete"
        return is_complete.is_file()

    @abstractmethod
    def download_dataset(self) -> None:
        """Download or prepare the dataset's source files.

        This method must be implemented by subclasses to define how the
        dataset's source files (e.g., from Git, archives) are obtained
        and placed in the appropriate directory.
        """
        pass

    @abstractmethod
    def load_dataset(self) -> list[File]:
        """Load the dataset into memory.

        This method must be implemented by subclasses to define how the
        dataset's contents are loaded.

        Returns:
            A list of `File` objects representing the dataset.

        """
        pass

    @classmethod
    def list_dataset(cls) -> list[str]:
        """List all available language-specific versions of this dataset.

        Returns:
            A sorted list of strings, where each string is the dataset name
            suffixed with a supported language (e.g., "MyDataset_java").

        """
        return sorted([f"{cls.name}_{lang}" for lang in cls.supported_languages])


class DatasetUnit:
    """Base class for a single unit within a dataset.

    Serves as a marker class for items like `File` or `GitRepo`.
    """

    pass


class BenchmarkData:
    """Base class for storing data resulting from a benchmark.

    Serves as a marker class for data holders like `FileDatasetData` or
    `GitRepoDatasetData`.
    """

    pass


class File(DatasetUnit):
    """Represents a single file in a dataset.

    Attributes:
        filename (str): The name of the file.
        content (bytes): The byte content of the file.
        cwe_ids (list[int]): A list of CWE IDs associated with vulnerabilities
            in the file.
        is_real (bool): True if the vulnerability is real, False if it's
            intended to be a false positive test case.

    """

    def __init__(
        self, filename: str, content: str | bytes, cwe_ids: list[int], is_real: bool
    ) -> None:
        """Initialize a File instance.

        Args:
            filename: The name of the file.
            content: The content of the file, as a string or bytes. It will be
                converted to bytes if provided as a string.
            cwe_ids: A list of CWE IDs associated with the file.
            is_real: True if the vulnerability is real, False if it's
                intended to be a false positive test case.

        """
        self.filename = filename
        self.content = content
        self.cwe_ids = cwe_ids
        self.is_real = is_real

        if isinstance(content, str):
            self.content = content.encode()

    def __repr__(self) -> str:
        """Provide a developer-friendly string representation of the File.

        Returns:
            A string showing the class name, filename, and CWE IDs.

        """
        return f"""{self.__class__.__name__}(
    filename: \t{self.filename}
    cwe_ids: \t{self.cwe_ids}
)"""

    def __eq__(self, other: str | Self) -> bool:
        """Compare this File with another object for equality based on filename.

        Args:
            other: The object to compare with. Can be a string (filename) or
                   another File instance.

        Returns:
            True if the filenames are equal, False otherwise.

        """
        if isinstance(other, str):
            return self.filename == other
        elif isinstance(other, self.__class__):
            return self.filename == other.filename
        else:
            return False

    def save(self, dir: Path) -> None:
        """Save the file's content to a specified directory.

        Args:
            dir: The path to the directory where the file should be saved.

        """
        (dir / self.filename).write_bytes(self.content)


class FileDataset(Dataset):
    """Abstract base class for datasets composed of individual files.

    Attributes:
        directory (Path): The directory path for the dataset.
        lang (str): The programming language of the dataset.
        full_name (str): The full name of the dataset, including the language.
        files (list[File]): A list of `File` objects loaded from the dataset.

    """

    def __init__(self, lang: str) -> None:
        """Initialize a FileDataset instance.

        Args:
            lang: The programming language of the dataset to load.

        """
        super().__init__(lang)

    def validate(self, analysis_result: AnalysisResult) -> FileDatasetData:
        """Validate a SAST analysis result against the ground truth of the dataset.

        Compare the defects found by a SAST tool with the known vulnerabilities
        in the dataset files to categorize them as true positives, false positives, etc.

        Args:
            analysis_result: The result from a SAST tool analysis.

        Returns:
            A `FileDatasetData` object containing the validation metrics.

        """
        files = self.files

        file_cwes = {file.filename: file.cwe_ids for file in files}
        file_is_real = {file.filename: file.is_real for file in files}

        file_number = len(files)
        defect_number = len(analysis_result.defects)
        cwes_list = [cwe_id for file in files for cwe_id in file.cwe_ids]

        correct_defects = []
        incorrect_defects = []

        correct_cwes = []
        incorrect_cwes = []
        for defect in analysis_result.defects:
            # Ignore defect without cwe_id
            if not defect.cwe_id:
                continue

            # Identified vulns
            if defect.cwe_id in file_cwes[defect.file]:
                if file_is_real[defect.file]:
                    # True Positive
                    correct_defects.append(defect)
                    correct_cwes.append(defect.cwe_id)
                else:
                    # False Positive
                    incorrect_defects.append(defect)
                    incorrect_cwes.append(defect.cwe_id)
            # Not identified vulns
            else:
                if not file_is_real[defect.file]:
                    # True negative (not identified and there was indeed no vuln)
                    correct_defects.append(defect)
                    correct_cwes.append(defect.cwe_id)
                else:
                    # Flase Negative (not identified and there was a vuln)
                    incorrect_defects.append(defect)
                    incorrect_cwes.append(defect.cwe_id)

        unique_correct_number = len(set(defect.file for defect in correct_defects))

        return FileDatasetData(
            dataset=self,
            correct_defects=correct_defects,
            incorrect_defects=incorrect_defects,
            cwes_list=cwes_list,
            correct_cwes=correct_cwes,
            incorrect_cwes=incorrect_cwes,
            file_number=file_number,
            defect_number=defect_number,
            unique_correct_number=unique_correct_number,
        )


class FileDatasetData(BenchmarkData):
    """Stores the results of validating an analysis against a FileDataset.

    Attributes:
        dataset (FileDataset): The dataset used for the benchmark.
        correct_defects (list[Defect]): Defects correctly identified.
        incorrect_defects (list[Defect]): Defects incorrectly identified.
        cwes_list (list[int]): All CWEs present in the dataset's ground truth.
        correct_cwes (list[int]): CWEs of correctly identified defects.
        incorrect_cwes (list[int]): CWEs of incorrectly identified defects.
        file_number (int): Total number of files in the dataset.
        defect_number (int): Total number of defects reported by the tool.
        unique_correct_number (int): Number of files with at least one
            correctly identified defect.

    """

    def __init__(
        self,
        dataset: FileDataset,
        correct_defects: list[Defect],
        incorrect_defects: list[Defect],
        cwes_list: list[int],
        correct_cwes: list[int],
        incorrect_cwes: list[int],
        file_number: int,
        defect_number: int,
        unique_correct_number: int,
    ) -> None:
        """Initialize a FileDatasetData instance.

        Args:
            dataset: The dataset used for the benchmark.
            correct_defects: A list of correctly identified defects.
            incorrect_defects: A list of incorrectly identified defects.
            cwes_list: A list of all ground-truth CWEs in the dataset.
            correct_cwes: A list of CWEs from correct identifications.
            incorrect_cwes: A list of CWEs from incorrect identifications.
            file_number: The total number of files in the dataset.
            defect_number: The total number of defects found by the analysis.
            unique_correct_number: The number of files with at least one
                correctly identified vulnerability.

        """
        self.dataset = dataset
        self.correct_defects = correct_defects
        self.incorrect_defects = incorrect_defects
        self.cwes_list = cwes_list
        self.correct_cwes = correct_cwes
        self.incorrect_cwes = incorrect_cwes
        self.file_number = file_number
        self.defect_number = defect_number
        self.unique_correct_number = unique_correct_number


class GitRepo(DatasetUnit):
    """Represents a single Git repository in a dataset.

    Attributes:
        name (str): A unique name for the repository, often a CVE ID.
        url (str): The URL to clone the Git repository.
        commit (str): The specific commit hash to check out.
        size (int): The size of the repository in bytes.
        cwe_ids (list[int]): A list of CWE IDs associated with the commit.
        files (list[str]): A list of filenames known to be vulnerable in
            this commit.

    """

    def __init__(
        self,
        name: str,
        url: str,
        commit: str,
        size: int,
        cwe_ids: list[int],
        files: list[str],
    ) -> None:
        """Initialize a GitRepo instance.

        Args:
            name: The name/identifier for the repository.
            url: The clone URL of the repository.
            commit: The commit hash to analyze.
            size: The size of the repository in bytes.
            cwe_ids: A list of associated CWE IDs.
            files: A list of vulnerable files in the specified commit.

        """
        self.name = name
        self.url = url
        self.commit = commit
        self.size = size
        self.cwe_ids = cwe_ids
        self.files = files

    def __repr__(self) -> str:
        """Provide a developer-friendly string representation of the GitRepo.

        Returns:
            A string showing the repo's name, URL, commit, size, CWEs, and files.

        """
        return f"""{self.__class__.__name__}(
    name: \t{self.name}
    url: \t{self.url}
    commit: \t{self.commit}
    size: \t{humanize.naturalsize(self.size)}
    cwe_ids: \t{self.cwe_ids}
    files: \t{self.files}
)"""

    def __eq__(self, other: str | Self) -> bool:
        """Compare this GitRepo with another object for equality based on name.

        Args:
            other: The object to compare with. Can be a string (repo name) or
                   another GitRepo instance.

        Returns:
            True if the names are equal, False otherwise.

        """
        if isinstance(other, str):
            return self.name == other
        elif isinstance(other, self.__class__):
            return self.name == other.name
        else:
            return False

    def save(self, dir: Path) -> None:
        """Clone the repository and check out the specific commit.

        Args:
            dir: The path to the directory where the repository should be cloned.

        """
        repo = git.Repo.clone_from(self.url, dir)
        repo.git.checkout(self.commit)


class GitRepoDataset(Dataset):
    """Abstract base class for datasets composed of Git repositories.

    Attributes:
        directory (Path): The directory path for the dataset.
        lang (str): The programming language of the dataset.
        full_name (str): The full name of the dataset, including the language.
        repos (list[GitRepo]): A list of `GitRepo` objects loaded from the dataset.
        max_repo_size (int): The maximum repository size to consider for analysis.

    """

    def __init__(self, lang: str) -> None:
        """Initialize a GitRepoDataset instance.

        Args:
            lang: The programming language of the dataset to load.

        """
        super().__init__(lang)
        self.repos: list[GitRepo] = self.files
        self.max_repo_size: int

    def validate(self, analysis_results: list[AnalysisResult]) -> GitRepoDatasetData:
        """Validate SAST analysis results against the ground truth of the dataset.

        Compare the defects found by a SAST tool for each repository with the
        known vulnerabilities (CWEs and file locations) in the dataset to
        categorize them as correct, partial, or incorrect.

        Args:
            analysis_results: A list of analysis results, one for each repository.

        Returns:
            A `GitRepoDatasetData` object containing the validation metrics.

        """
        total_repo_number = len(self.repos)
        defect_numbers = sum([len(ar.defects) for ar in analysis_results])
        validated_repos = []

        for analysis_result in analysis_results:
            repo = self.repos[self.repos.index(analysis_result.name)]

            correct_defects = []
            partial_defects = []
            incorrect_defects = []

            correct_cwes = []
            incorrect_cwes = []
            for defect in analysis_result.defects:
                # Ignore defect without cwe_id
                if not defect.cwe_id:
                    continue

                # Found vulnerable file and the right CWE
                if defect.file in repo.files and defect.cwe_id in repo.cwe_ids:
                    correct_defects.append(defect)
                    correct_cwes.append(defect.cwe_id)
                # Found vulnerable file but not for the right reason
                elif defect.file in repo.files and defect.file:
                    partial_defects.append(defect)
                    incorrect_cwes.append(defect.cwe_id)
                # False positive
                else:
                    incorrect_defects.append(defect)
                    incorrect_cwes.append(defect.cwe_id)

            result = {
                "correct_defects": correct_defects,
                "partial_defects": partial_defects,
                "incorrect_defects": incorrect_defects,
                "cwes_list": repo.cwe_ids,
                "correct_cwes": correct_cwes,
                "incorrect_cwes": incorrect_cwes,
                "time": analysis_result.time,
                "loc": analysis_result.loc,
            }
            validated_repos.append(result)

        return GitRepoDatasetData(
            dataset=self,
            validated_repos=validated_repos,
            total_repo_number=total_repo_number,
            defect_numbers=defect_numbers,
        )


class GitRepoDatasetData(BenchmarkData):
    """Stores the results of validating an analysis against a GitRepoDataset.

    Attributes:
        dataset (GitRepoDataset): The dataset used for the benchmark.
        validated_repos (list[dict]): A list of dictionaries, each containing
            the validation results for a single repository.
        total_repo_number (int): The total number of repositories in the dataset.
        defect_numbers (int): The total number of defects found across all repos.

    """

    def __init__(
        self,
        dataset: GitRepoDataset,
        validated_repos: list[dict],
        total_repo_number: int,
        defect_numbers: int,
    ) -> None:
        """Initialize a GitRepoDatasetData instance.

        Args:
            dataset: The dataset used for the benchmark.
            validated_repos: A list of validation results per repository.
            total_repo_number: The total number of repositories in the dataset.
            defect_numbers: The total number of defects found by the analysis.

        """
        self.dataset = dataset
        self.validated_repos = validated_repos
        self.total_repo_number = total_repo_number
        self.defect_numbers = defect_numbers
