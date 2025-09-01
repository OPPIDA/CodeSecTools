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
import typer
from rich import print
from rich.panel import Panel
from rich.progress import Progress

from codesectools.utils import USER_CACHE_DIR

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Self

    from codesectools.sasts.core.parser import AnalysisResult, Defect
    from codesectools.shared.cwe import CWE


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
    license: str
    license_url: str

    def __init__(self, lang: str | None = None) -> None:
        """Initialize the Dataset instance.

        Set up paths and load the dataset if a language is specified.

        Args:
            lang: The programming language of the dataset to load. Must be one
                of the supported languages for the dataset class.

        """
        self.directory = USER_CACHE_DIR / self.name
        self.lang = lang
        if self.lang:
            self.full_name = f"{self.name}_{self.lang}"
            assert self.full_name in self.list_dataset_full_names()
            self.files: list[File] = self.load_dataset()
        else:
            self.files = []

    @classmethod
    def is_cached(cls) -> bool:
        """Check if the dataset has been downloaded and is cached locally.

        Returns:
            True if the dataset is cached, False otherwise.

        """
        is_complete = USER_CACHE_DIR / cls.name / ".complete"
        return is_complete.is_file()

    def prompt_license_agreement(self) -> None:
        """Display the dataset's license and prompt the user for agreement."""
        panel = Panel(
            f"""Dataset:\t[b]{self.name}[/b]
License:\t[b]{self.license}[/b]
License URL:\t[u]{self.license_url}[/u]

Please review the license at the URL above.
By proceeding, you agree to abide by its terms.""",
            title="[b]License Agreement[/b]",
        )
        print(panel)

        agreed = typer.confirm("Do you accept the license terms and wish to proceed?")
        if not agreed:
            print("[red]License agreement declined. Download aborted.[/red]")
            raise typer.Exit(code=1)

    @abstractmethod
    def download_files(self) -> None:
        """Download the raw dataset files."""
        pass

    def download_dataset(self) -> None:
        """Handle the full dataset download process, including license prompt and caching."""
        self.prompt_license_agreement()
        with Progress() as progress:
            progress.add_task(f"[red]Downloading {self.name}...", total=None)
            self.download_files()
        (self.directory / ".complete").write_bytes(b"\x42")
        print(f"{self.name} has been downloaded at {self.directory}.")

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
    def list_dataset_full_names(cls) -> list[str]:
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
        cwes (list[CWE]): A list of CWEs associated with the file.
        is_real (bool): True if the vulnerability is real, False if it's
            intended to be a false positive test case.

    """

    def __init__(
        self, filename: str, content: str | bytes, cwes: list[CWE], is_real: bool
    ) -> None:
        """Initialize a File instance.

        Args:
            filename: The name of the file.
            content: The content of the file, as a string or bytes. It will be
                converted to bytes if provided as a string.
            cwes: A list of CWEs associated with the file.
            is_real: True if the vulnerability is real, False if it's
                intended to be a false positive test case.

        """
        self.filename = filename
        self.content = content
        self.cwes = cwes
        self.is_real = is_real

        if isinstance(content, str):
            self.content = content.encode()

    def __repr__(self) -> str:
        """Return a developer-friendly string representation of the File.

        Returns:
            A string showing the class name, filename, and CWE IDs.

        """
        return f"""{self.__class__.__name__}(
    filename: \t{self.filename}
    cwes: \t{self.cwes}
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

        Compares the defects found by a SAST tool with the known vulnerabilities
        in the dataset files to categorize them as true positives, false positives, and false negatives,
        counting each unique (file, CWE) pair only once.

        Args:
            analysis_result: The result from a SAST tool analysis.

        Returns:
            A `FileDatasetData` object containing the validation metrics.

        """
        # 1. Prepare ground truth data from vulnerable files (`is_real=True`)
        ground_truth_vulns: dict[str, set[CWE]] = {}
        for file in self.files:
            if file.is_real:
                ground_truth_vulns[file.filename] = set(file.cwes)

        # 2. Process reported defects to get unique (file, cwe) pairs
        unique_reported_vulns: dict[str, set[CWE]] = {}
        # Keep one original Defect object for each unique finding to retain metadata
        original_defects_map: dict[tuple[str, CWE], Defect] = {}

        for defect in analysis_result.defects:
            # Ignore defects without a valid CWE
            if not defect.cwe or defect.cwe.id == -1:
                continue

            file_cwe_pair = (defect.file, defect.cwe)

            # If we haven't seen this specific vulnerability (file + cwe) before...
            if file_cwe_pair not in original_defects_map:
                original_defects_map[file_cwe_pair] = defect

                if defect.file not in unique_reported_vulns:
                    unique_reported_vulns[defect.file] = set()
                unique_reported_vulns[defect.file].add(defect.cwe)

        # 3. Classify unique reported vulnerabilities
        tp_defects_set: set[tuple[str, CWE]] = set()
        fp_defects_set: set[tuple[str, CWE]] = set()

        for filename, reported_cwes in unique_reported_vulns.items():
            expected_cwes = ground_truth_vulns.get(filename, set())

            # True Positives are reported CWEs that match the ground truth for that file.
            tp_for_file = reported_cwes.intersection(expected_cwes)
            for cwe in tp_for_file:
                tp_defects_set.add((filename, cwe))

            # False Positives are reported CWEs that do not match the ground truth.
            # This includes findings in non-vulnerable files or with incorrect CWEs.
            fp_for_file = reported_cwes.difference(expected_cwes)
            for cwe in fp_for_file:
                fp_defects_set.add((filename, cwe))

        # 4. Determine False Negatives by finding what was missed from the ground truth.
        fn_defects_set: set[tuple[str, CWE]] = set()
        for filename, expected_cwes in ground_truth_vulns.items():
            reported_cwes = unique_reported_vulns.get(filename, set())
            missed_cwes = expected_cwes.difference(reported_cwes)
            for cwe in missed_cwes:
                fn_defects_set.add((filename, cwe))

        # 5. Convert sets back to lists of objects for downstream use
        tp_defects = [original_defects_map[pair] for pair in tp_defects_set]
        fp_defects = [original_defects_map[pair] for pair in fp_defects_set]
        fn_defects = list(fn_defects_set)

        # 6. Prepare data for the result object
        file_number = len(self.files)
        defect_number = len(
            analysis_result.defects
        )  # Total defects reported by the tool
        cwes_list = [cwe for file in self.files if file.is_real for cwe in file.cwes]

        tp_cwes = [cwe for _, cwe in tp_defects_set]
        fp_cwes = [cwe for _, cwe in fp_defects_set]
        fn_cwes = [cwe for _, cwe in fn_defects_set]

        unique_correct_number = len({filename for filename, _ in tp_defects_set})

        return FileDatasetData(
            dataset=self,
            tp_defects=tp_defects,
            fp_defects=fp_defects,
            fn_defects=fn_defects,
            cwes_list=cwes_list,
            tp_cwes=tp_cwes,
            fp_cwes=fp_cwes,
            fn_cwes=fn_cwes,
            file_number=file_number,
            defect_number=defect_number,
            unique_correct_number=unique_correct_number,
        )


class FileDatasetData(BenchmarkData):
    """Store the results of validating an analysis against a FileDataset.

    The counts for true positives, false positives, and false negatives are based on
    unique (file, CWE) pairs.

    Attributes:
        dataset (FileDataset): The dataset used for the benchmark.
        tp_defects (list[Defect]): A list of unique, correctly identified defects (True Positives).
        fp_defects (list[Defect]): A list of unique, incorrectly identified defects (False Positives).
        fn_defects (list[tuple[str, CWE]]): A list of unique vulnerabilities that were not found (False Negatives).
        cwes_list (list[CWE]): All CWEs present in the dataset's ground truth (may contain duplicates if a CWE appears in multiple files).
        tp_cwes (list[CWE]): List of CWEs from True Positive findings.
        fp_cwes (list[CWE]): List of CWEs from False Positive findings.
        fn_cwes (list[CWE]): List of CWEs from False Negative findings (missed vulnerabilities).
        file_number (int): Total number of files in the dataset.
        defect_number (int): Total number of defects reported by the tool (before de-duplication).
        unique_correct_number (int): Number of files with at least one
            correctly identified defect.

    """

    def __init__(
        self,
        dataset: FileDataset,
        tp_defects: list[Defect],
        fp_defects: list[Defect],
        fn_defects: list[tuple[str, CWE]],
        cwes_list: list[CWE],
        tp_cwes: list[CWE],
        fp_cwes: list[CWE],
        fn_cwes: list[CWE],
        file_number: int,
        defect_number: int,
        unique_correct_number: int,
    ) -> None:
        """Initialize a FileDatasetData instance.

        Args:
            dataset: The dataset used for the benchmark.
            tp_defects: A list of unique, correctly identified defects.
            fp_defects: A list of unique, incorrectly identified defects.
            fn_defects: A list of unique vulnerabilities that were not found.
            cwes_list: A list of all ground-truth CWEs in the dataset.
            tp_cwes: A list of CWEs from True Positive findings.
            fp_cwes: A list of CWEs from False Positive findings.
            fn_cwes: A list of CWEs from missed vulnerabilities.
            file_number: The total number of files in the dataset.
            defect_number: The total number of defects found by the analysis (before de-duplication).
            unique_correct_number: The number of files with at least one
                correctly identified vulnerability.

        """
        self.dataset = dataset
        self.tp_defects = tp_defects
        self.fp_defects = fp_defects
        self.fn_defects = fn_defects
        self.cwes_list = cwes_list
        self.tp_cwes = tp_cwes
        self.fp_cwes = fp_cwes
        self.fn_cwes = fn_cwes
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
        cwes (list[CWE]): A list of CWEs associated with the repository.
        files (list[str]): A list of filenames known to be vulnerable in
            this commit.

    """

    def __init__(
        self,
        name: str,
        url: str,
        commit: str,
        size: int,
        cwes: list[CWE],
        files: list[str],
    ) -> None:
        """Initialize a GitRepo instance.

        Args:
            name: The name/identifier for the repository.
            url: The clone URL of the repository.
            commit: The commit hash to analyze.
            size: The size of the repository in bytes.
            cwes: A list of CWEs associated with the repository.
            files: A list of vulnerable files in the specified commit.

        """
        self.name = name
        self.url = url
        self.commit = commit
        self.size = size
        self.cwes = cwes
        self.files = files

    def __repr__(self) -> str:
        """Return a developer-friendly string representation of the GitRepo.

        Returns:
            A string showing the repo's name, URL, commit, size, CWEs, and files.

        """
        return f"""{self.__class__.__name__}(
    name: \t{self.name}
    url: \t{self.url}
    commit: \t{self.commit}
    size: \t{humanize.naturalsize(self.size)}
    cwes: \t{self.cwes}
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
        categorize them as true positives and false positives.

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

            # De-duplicate defects from the tool per repo to count unique findings
            unique_defects = {
                (d.file, d.cwe): d
                for d in analysis_result.defects
                if d.cwe and d.cwe.id != -1
            }

            tp_defects = []
            fp_defects = []

            for (filename, cwe), defect in unique_defects.items():
                # True Positive: vulnerable file and correct CWE
                if filename in repo.files and cwe in repo.cwes:
                    tp_defects.append(defect)
                # False Positive: vulnerable file but wrong CWE, or not a vulnerable file
                else:
                    fp_defects.append(defect)

            # Extract CWEs for each category
            tp_cwes = [d.cwe for d in tp_defects]
            fp_cwes = [d.cwe for d in fp_defects]

            # Determine False Negatives: ground truth CWEs that were not found correctly
            ground_truth_cwes = set(repo.cwes)
            found_tp_cwes = set(tp_cwes)
            fn_defects = list(ground_truth_cwes - found_tp_cwes)

            result = {
                "tp_defects": tp_defects,
                "fp_defects": fp_defects,
                "fn_defects": fn_defects,
                "cwes_list": repo.cwes,
                "tp_cwes": tp_cwes,
                "fp_cwes": fp_cwes,
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
    """Store the results of validating an analysis against a GitRepoDataset.

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
