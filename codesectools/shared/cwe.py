"""Loads Common Weakness Enumeration (CWE) data from CSV files.

This module reads all CSV files starting with 'CWE_' from its directory,
parses them, and populates a dictionary with CWE details, keyed by CWE ID.

Attributes:
    CWE (dict): A dictionary where keys are integer CWE IDs and values are
        dictionaries containing the details for that CWE.

"""

import csv

from codesectools.utils import DATA_DIR

CWE = {}
for file_path in (DATA_DIR / "cwe").glob("CWE_*.csv"):
    with open(file_path, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            CWE[int(row["CWE-ID"])] = row
