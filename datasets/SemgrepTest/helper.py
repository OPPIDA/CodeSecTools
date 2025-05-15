from utils import *

DATASET_NAME = "SemgrepTest"
Semgrep_DATASET_DIR = os.path.join("datasets", DATASET_NAME)

class Rule:
    def __init__(self, id, content, cwe_ids):
        self.id = id
        self.content = content
        self.cwe_ids = cwe_ids

    def __repr__(self):
        return f"""{self.__class__.__name__}(
    id: \t{self.id}
    cwe_ids: \t{self.cwe_ids}
)"""

    def __eq__(self, other):
        if isinstance(other, str):
            return self.id == other
        elif isinstance(other, self.__class__):
            return self.id == other.id

class TestCode:
    def __init__(self, id, filename, content, cwe_ids):
        self.id = id
        self.filename = filename
        self.content = content
        self.cwe_ids = cwe_ids

    def __repr__(self):
        return f"""{self.__class__.__name__}(
    id: \t{self.id}
    filename: \t{self.filename}
    cwe_ids: \t{self.cwe_ids}
)"""

    def __eq__(self, other):
        if isinstance(other, str):
            return self.filename == other
        elif isinstance(other, self.__class__):
            return self.filename == other.filename

    def save(self, dir):
        with open(os.path.join(dir, self.filename), 'w') as file:
            file.write(self.content)

## Methods
def list_dataset():
    return sorted(
        [
            "SemgrepTest_java"
        ]
    )

def load_dataset(lang):
    with open(os.path.join(Semgrep_DATASET_DIR, "Semgrep_all.json")) as file:
        SEMGREP_RULES = json.load(file)

    rules = []
    testcodes = []
    for rule in SEMGREP_RULES:
        cwes = rule['definition']['rules'][0]['metadata'].get('cwe')
        if not cwes: continue
        if isinstance(cwes, str): cwes = [cwes]

        cwe_ids = []
        for cwe in cwes:
            cwe_ids.append(int(re.search(r'[CWE|cwe]-(\d+)', cwe).group(1)))

        rule_id = rule['path']
        languages = rule['definition']['rules'][0]['languages']
        if not lang in languages: continue

        rules.append(
            Rule(rule_id, rule['definition'], cwe_ids)
        )

        if rule.get('test_cases'):
            for test in rule['test_cases']:
                if lang == test['language']:
                    testcodes.append(
                        TestCode(rule_id, test['filename'], test['target'], cwe_ids)
                    )

    return rules, testcodes