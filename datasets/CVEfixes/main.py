from utils import *


class CVE:
    def __init__(self, cve_id, cwe_ids, cwe_descriptions, repo_url, parents, filenames, repo_size):
        self.cve_id = cve_id
        self.cwe_ids = cwe_ids
        self.cwe_descriptions = cwe_descriptions
        self.cwes = list(zip(cwe_ids, cwe_descriptions))
        self.repo_url = repo_url
        self.parents = parents
        self.filenames = filenames
        self.repo_size = repo_size

    def __repr__(self):
        return f"{self.__class__.__name__}({self.cve_id})"

CVEfixes_DATASET_DIR = os.path.join("datasets", "CVEfixes")

## Methods
def list_dataset():
    return sorted(
        list(
            map(
                os.path.basename,
                glob.glob(os.path.join(CVEfixes_DATASET_DIR, "CVEfixes_*.csv"))
            )
        )
    )

def load_dataset(lang):
    dataset_path = os.path.join(CVEfixes_DATASET_DIR, f"CVEfixes_{lang}.csv")

    CVEs = []
    with open(dataset_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve = CVE(
                cve_id=row['cve_id'],
                cwe_ids=row['cwe_ids'].split(';'),
                cwe_descriptions=row['cwe_descriptions'].split(';'),
                repo_url=row['repo_url'],
                parents=eval(row['parents']),
                filenames=row['filenames'].split(';'),
                repo_size=int(row['repo_size']),
            )
            CVEs.append(cve)

    return CVEs