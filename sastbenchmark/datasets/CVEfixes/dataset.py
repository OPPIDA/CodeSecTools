import csv

from sastbenchmark.datasets._base.dataset import GitRepo, GitRepoDataset


class CVEfixes(GitRepoDataset):
    name = "CVEfixes"
    supported_languages = ["java"]

    def __init__(self, lang: str) -> None:
        self.max_repo_size = 100e6
        super().__init__(lang)

    def load_dataset(
        self,
    ) -> list[GitRepo]:
        dataset_path = self.directory / "data" / f"CVEfixes_{self.lang}.csv"
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
