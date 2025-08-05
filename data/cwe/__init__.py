import csv
import glob
import os

CWE = {}
for file_path in glob.glob(os.path.join("data", "cwe", "CWE_*.csv")):
    with open(file_path, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            CWE[int(row["CWE-ID"])] = row
