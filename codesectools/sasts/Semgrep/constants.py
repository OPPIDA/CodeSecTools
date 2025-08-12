"""Defines constants for the Semgrep integration.

This module specifies supported datasets, languages, and color mappings
for plotting results from Semgrep scans.
"""

## Support
SUPPORTED_DATASETS = ["BenchmarkJava", "CVEfixes"]

LANGUAGES = {"java": {}}

## Ploting
COLOR_MAPPING = {
    "security": "RED",
    "correctness": "ORANGE",
    "best-practice": "YELLOW",
    "performance": "GREEN",
    "maintainability": "CYAN",
    "portability": "GRAY",
}
