import csv
import glob
import os

from sastbenchmark.utils import PACKAGE_DIR

CWE = {}
for file_path in glob.glob(os.path.join(PACKAGE_DIR, "data", "cwe", "CWE_*.csv")):
    with open(file_path, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            CWE[int(row["CWE-ID"])] = row
