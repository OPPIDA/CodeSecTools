from utils import *

## Data
SEMGREP_DIR = os.path.join(WORKING_DIR, "Semgrep")
SEMGREP_DATA = os.path.join(SEMGREP_DIR, "data")
SEMGREP_RULES_DIR = os.path.join(SEMGREP_DATA, "rules")

## Results
RESULT_DIR = os.path.join("results", "Semgrep")
CVEfixes_RESULT_DIR = os.path.join(RESULT_DIR, "CVEfixes")
BenchmarkJava_RESULT_DIR = os.path.join(RESULT_DIR, "BenchmarkJava")

SUPPORTED_DATASETS = ["BenchmarkJava"]

## Supported languages
LANG = {"java": {}}

## Ploting
COLOR_MAPPING = {
    "security": "RED",
    "correctness": "ORANGE",
    "best-practice": "YELLOW",
    "performance": "GREEN",
    "maintainability": "CYAN",
    "portability": "GRAY",
}
