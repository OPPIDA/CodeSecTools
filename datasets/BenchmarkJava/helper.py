from utils import *

DATASET_NAME = "BenchmarkJava"
BenchmarkJava_DATASET_DIR = os.path.join("datasets", DATASET_NAME)
TEST_CODE_DIR = os.path.join(BenchmarkJava_DATASET_DIR, "src/main/java/org/owasp/benchmark/testcode")

class TestCode:
    def __init__(self, name, vuln_type, is_real, cwe_id):
        self.name = name
        self.content = open(os.path.join(TEST_CODE_DIR, f"{name}.java")).read()
        self.vuln_type = vuln_type
        self.is_real = is_real
        self.cwe_ids = [cwe_id]

    def __repr__(self):
        return f"""{self.__class__.__name__}(
    name: \t{self.name}
    vuln_type: \t{self.vuln_type}
    is_real: \t{self.is_real}
    cwe_ids: \t{self.cwe_ids}
)"""

    def __eq__(self, other):
        if isinstance(other, str):
            return self.name == other
        elif isinstance(other, self.__class__):
            return self.name == other.name

    def save(self, dir):
        with open(os.path.join(dir, f"{self.name}.java"), 'w') as file:
            file.write(self.content)

## Methods
def list_dataset():
    return sorted(
        [
            "BenchmarkJava"
        ]
    )

def load_dataset():
    testcodes = []

    with open(os.path.join(BenchmarkJava_DATASET_DIR, "expectedresults-1.2.csv"), "r") as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            testcodes.append(TestCode(row[0], row[1], row[2], row[3]))

    return testcodes
