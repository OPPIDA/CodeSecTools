from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

import git
import humanize

from sastbenchmark.utils import PACKAGE_DIR

if TYPE_CHECKING:
    from typing import Self

    from sastbenchmark.sasts._base.parser import AnalysisResult, Defect

DATASETS_DIR = PACKAGE_DIR / "datasets"


class Dataset(ABC):
    @abstractmethod
    def load_dataset(self) -> list[File]:
        pass

    @staticmethod
    @abstractmethod
    def list_dataset() -> list[str]:
        pass


class DatasetUnit:
    pass


class BenchmarkData:
    pass


class File(DatasetUnit):
    def __init__(
        self, filename: str, content: str | bytes, cwe_ids: list[int], is_real: bool
    ) -> None:
        self.filename = filename
        self.content = content
        self.cwe_ids = cwe_ids
        self.is_real = is_real

        if isinstance(content, str):
            self.content = content.encode()

    def __repr__(self) -> str:
        return f"""{self.__class__.__name__}(
    filename: \t{self.filename}
    cwe_ids: \t{self.cwe_ids}
)"""

    def __eq__(self, other: str | Self) -> bool:
        if isinstance(other, str):
            return self.filename == other
        elif isinstance(other, self.__class__):
            return self.filename == other.filename
        else:
            return False

    def save(self, dir: str) -> None:
        with open(os.path.join(dir, self.filename), "wb") as file:
            file.write(self.content)


class FileDataset(Dataset):
    name = ""

    def __init__(self, lang: str) -> None:
        self.directory = os.path.join(DATASETS_DIR, self.name)
        if lang:
            self.lang = lang
            self.full_name = f"{self.name}_{self.lang}"
            assert self.full_name in self.list_dataset()
            self.files: list[File] = self.load_dataset()

    def validate(self, analysis_result: AnalysisResult) -> FileDatasetData:
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
    def __init__(
        self,
        name: str,
        url: str,
        commit: str,
        size: int,
        cwe_ids: list[int],
        files: list[str],
    ) -> None:
        self.name = name
        self.url = url
        self.commit = commit
        self.size = size
        self.cwe_ids = cwe_ids
        self.files = files

    def __repr__(self) -> str:
        return f"""{self.__class__.__name__}(
    name: \t{self.name}
    url: \t{self.url}
    commit: \t{self.commit}
    size: \t{humanize.naturalsize(self.size)}
    cwe_ids: \t{self.cwe_ids}
    files: \t{self.files}
)"""

    def __eq__(self, other: str | Self) -> bool:
        if isinstance(other, str):
            return self.name == other
        elif isinstance(other, self.__class__):
            return self.name == other.name
        else:
            return False

    def save(self, dir: str) -> None:
        repo = git.Repo.clone_from(self.url, dir)
        repo.git.checkout(self.commit)


class GitRepoDataset(Dataset):
    name = ""

    def __init__(self, lang: str) -> None:
        self.directory = os.path.join(DATASETS_DIR, self.name)
        if lang:
            self.lang = lang
            self.full_name = f"{self.name}_{self.lang}"
            assert self.full_name in self.list_dataset()
            self.repos = self.load_dataset()
        self.max_repo_size: int

    def validate(self, analysis_results: list[AnalysisResult]) -> GitRepoDatasetData:
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
    def __init__(
        self,
        dataset: GitRepoDataset,
        validated_repos: list[dict],
        total_repo_number: int,
        defect_numbers: int,
    ) -> None:
        self.dataset = dataset
        self.validated_repos = validated_repos
        self.total_repo_number = total_repo_number
        self.defect_numbers = defect_numbers
