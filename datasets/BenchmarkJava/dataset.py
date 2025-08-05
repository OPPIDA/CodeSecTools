import csv
import os
import zipfile
from typing import Self

from datasets._base.dataset import File, FileDataset


class TestFile(File):
    def __init__(
        self,
        filename: str,
        content: str | bytes,
        cwe_ids: list[int],
        vuln_type: str,
        is_real: bool,
    ):
        super().__init__(
            filename=filename, content=content, cwe_ids=cwe_ids, is_real=is_real
        )

        self.vuln_type = vuln_type


class BenchmarkJava(FileDataset):
    name = "BenchmarkJava"

    def __init__(self, lang: None | str = None):
        super().__init__(lang)

    def __eq__(self, other: str | Self):
        if isinstance(other, str):
            return self.name == other
        elif isinstance(other, self.__class__):
            return self.name == other.name

    def load_dataset(self) -> list[TestFile]:
        files = []
        testfiles = zipfile.ZipFile(
            open(
                os.path.join(self.directory, "data", "tests.zip"),
                "rb",
            )
        )
        expected_results = open(
            os.path.join(self.directory, "data", "expectedresults-1.2.csv"), "r"
        )
        reader = csv.reader(expected_results)
        next(reader)
        for row in reader:
            filename = f"{row[0]}.java"
            content = testfiles.open(filename).read()
            cwe_ids = [int(row[3])]
            vuln_type = row[1]
            is_real = True if row[2] == "true" else False
            files.append(TestFile(filename, content, cwe_ids, vuln_type, is_real))

        return files

    @staticmethod
    def list_dataset() -> list[str]:
        return sorted(["BenchmarkJava_java"])
