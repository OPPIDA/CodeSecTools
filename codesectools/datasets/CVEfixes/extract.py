"""Extracts and prepares language-specific subsets of the CVEfixes dataset.

This script connects to the CVEfixes SQLite database, queries for vulnerability
data related to a specific programming language, fetches repository size
information from the GitHub API, and saves the result as a CSV file.

A GitHub personal access token is required to use the GitHub API.
"""

import csv
import sqlite3
import sys

import requests
import tqdm

from codesectools.utils import PACKAGE_DIR

CVEfixes_DATASET_DIR = PACKAGE_DIR / "datasets" / "CVEfixes"

LANG_EXT = {"java": ["java"]}


def get_github_repo_size(repo_url: str) -> int | None:
    """Fetch the size of a GitHub repository via the GitHub API.

    Args:
        repo_url: The URL of the GitHub repository (e.g., "https://github.com/user/repo").

    Returns:
        The size of the repository in bytes, or None if the API call fails or
        the size is not available.

    """
    headers = {"Authorization": f"Bearer {TOKEN}"}
    r = requests.get(
        repo_url.replace("github.com", "api.github.com/repos"), headers=headers
    )
    size_kb = r.json().get("size", None)
    if size_kb:
        return size_kb * 1000


def extract_lang(lang: str) -> None:
    """Extract data for a specific language from the CVEfixes database.

    Queries the database, fetches repository sizes, and writes the
    combined data to a CSV file.

    Args:
        lang: The programming language to extract (e.g., "java").

    """
    conn = sqlite3.connect(PACKAGE_DIR / "datasets" / "CVEfixes" / "CVEfixes.db")
    cursor = conn.cursor()
    query = f"""
SELECT
    cve.cve_id,
    REPLACE(GROUP_CONCAT(DISTINCT cwe.cwe_id), ',', ';') AS cwe_ids,
    REPLACE(GROUP_CONCAT(DISTINCT cwe.description), ',', ';') AS cwe_descriptions,
    repository.repo_url,
    commits.parents,
    REPLACE(GROUP_CONCAT(DISTINCT file_change.filename), ',', ';') AS filenames
FROM cve
JOIN fixes ON fixes.cve_id = cve.cve_id
JOIN commits ON commits.hash = fixes.hash AND commits.repo_url = fixes.repo_url
JOIN file_change ON file_change.hash = commits.hash
JOIN repository ON repository.repo_url = commits.repo_url
JOIN cwe_classification ON cwe_classification.cve_id = cve.cve_id
JOIN cwe ON cwe.cwe_id = cwe_classification.cwe_id
WHERE LOWER(repository.repo_language) = '{lang}'
    AND cwe.cwe_id GLOB 'CWE-[0-9]*'"""

    for ext in LANG_EXT[lang]:
        query += f"""
    AND file_change.filename GLOB '*.{ext}'"""

    query += """
    AND file_change.filename NOT GLOB '*[Tt]est*'
GROUP BY cve.cve_id;"""
    cursor.execute(query)
    rows = cursor.fetchall()

    output_path = CVEfixes_DATASET_DIR / f"CVEfixes_{lang}.csv"
    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        headers = [desc[0] for desc in cursor.description] + ["repo_size"]
        writer.writerow(headers)

        for row in tqdm.tqdm(rows):
            repo_url = row[3]
            size = get_github_repo_size(repo_url)
            writer.writerow(list(row) + [size])

    print(f"Extraction completed and available at {output_path}")
    conn.close()


if __name__ == "__main__":
    TOKEN = input("Token: ")
    headers = {"Authorization": f"Bearer {TOKEN}"}
    r = requests.get("https://api.github.com", headers=headers)
    if r.status_code == 401:
        print(r.json())
        sys.exit(1)

    print("Available languages")
    for lang, _ in LANG_EXT.items():
        print(f"- {lang}")

    lang = input("Select lang: ")

    if lang not in LANG_EXT.keys():
        print(f"Lang {lang} not available")
    else:
        extract_lang(lang)
