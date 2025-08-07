import json
import os
import re

from sastbenchmark.datasets._base.dataset import File, FileDataset


class TestFile(File):
    def __init__(
        self,
        filename: str,
        content: str | bytes,
        cwe_ids: list[int],
        is_real: bool = True,
    ) -> None:
        super().__init__(
            filename=filename, content=content, cwe_ids=cwe_ids, is_real=True
        )


class SemgrepTest(FileDataset):
    name = "SemgrepTest"
    supported_languages = ["java"]

    def __init__(self, lang: str) -> None:
        super().__init__(lang)

    def load_dataset(self) -> list[TestFile]:
        with open(os.path.join(self.directory, "data", "Semgrep_all.json")) as file:
            SEMGREP_RULES = json.load(file)

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
