import csv
from git import Repo
import subprocess
import tempfile

class Vuln:
    def __init__(self, cve_id, cwe_ids, repo_url, parents, filenames):
        self.cve_id = cve_id
        self.cwe_ids = cwe_ids
        self.repo_url = repo_url
        self.parents = parents
        self.filenames = filenames

    def __repr__(self):
        return f"Vuln({self.cve_id}, {self.cwe_ids})"

# Parse CVEfixes dataset
filepath = "./datasets/CVEfixes_Java.csv"

vulns = []
with open(filepath, newline='', encoding='utf-8') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        vuln = Vuln(
            cve_id=row['cve_id'],
            cwe_ids=row['cwe_ids'].split(';'),
            repo_url=row['repo_url'],
            parents=eval(row['parents']),
            filenames=row['filenames'].split(';')
        )
        vulns.append(vuln)

vuln = vulns[0]

temp_dir = tempfile.TemporaryDirectory()
repo_path = temp_dir.name
repo = Repo.clone_from(vuln.repo_url, repo_path)
repo.git.checkout(vuln.parents[0])
r = subprocess.run("ls", cwd=repo_path, capture_output=True, text=True)
print(r)