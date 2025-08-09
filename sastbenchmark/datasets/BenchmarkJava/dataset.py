import csv
import zipfile
from typing import Self

from sastbenchmark.datasets.core.dataset import File, FileDataset


class TestFile(File):
    def __init__(
        self,
        filename: str,
        content: str | bytes,
        cwe_ids: list[int],
        vuln_type: str,
        is_real: bool,
    ) -> None:
        super().__init__(
            filename=filename, content=content, cwe_ids=cwe_ids, is_real=is_real
        )

        self.vuln_type = vuln_type


class BenchmarkJava(FileDataset):
    name = "BenchmarkJava"
    supported_languages = ["java"]

    def __init__(self, lang: None | str = None) -> None:
        super().__init__(lang)

    def __eq__(self, other: str | Self) -> bool:
        if isinstance(other, str):
            return self.name == other
        elif isinstance(other, self.__class__):
            return self.name == other.name
        else:
            return False

    def load_dataset(self) -> list[TestFile]:
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
