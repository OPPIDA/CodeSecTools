-- Extract minimal data from the dataset for SAST benchmarking
-- Language: Java
.headers on
.mode csv
.output CVEfixes_Java.csv
SELECT
  cve.cve_id,
  REPLACE(GROUP_CONCAT(DISTINCT cwe.cwe_id), ',', ';') AS cwe_ids,
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
WHERE repository.repo_language = 'Java'
  AND cwe.cwe_id GLOB 'CWE-[0-9]*'
  AND file_change.filename GLOB '*.java'
  AND file_change.filename NOT GLOB '*[Tt]est*'
GROUP BY cve.cve_id;