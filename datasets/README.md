# Datasets

You will find here datasets used for the benchmark.

## [CVEfixes](https://github.com/secureIT-project/CVEfixes)

Version: `v1.0.8`

CVEfixes dataset is ~50 GB big.

To avoid overloading SAST tool's environment, we extract the minimal data from the dataset:
- `cve_id`: for reference only,
- `cwe_ids`: compare with SAST output,
- `repo_url`: download the project,
- `parents`: checkout to the vulnerable version,
- `filenames`: compare with SAST output.

With following filter:
```sql
[...]
WHERE repository.repo_language = '$LANG'
  AND cwe.cwe_id GLOB 'CWE-[0-9]*'                -- Need CWE id to compare with SAST output
  AND file_change.filename GLOB '*.$EXT'
  AND file_change.filename NOT GLOB '*[Tt]est*'   -- Exclude test files
[...]
```

### Java

```bash
# Generate CVEfixes_Java.csv
sqlite3 CVEfixes.db < CVEfixes_Java.sql
```
 