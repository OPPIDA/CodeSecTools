# Datasets

You will find here datasets used for the benchmark.

- [Datasets](#datasets)
  - [Dataset components](#dataset-components)
  - [List of datasets](#list-of-datasets)
    - [1. CVEfixes](#1-cvefixes)
    - [2. Semgrep Test Code](#2-semgrep-test-code)
    - [3. BenchmarkJava](#3-benchmarkjava)

## Dataset components
*None of them are mandatory; they are provided solely as templates*

- `helper`:
  - load dataset
  - constants
- `stats`:
  - compare SAST results with expected results
  - generate plots for visualization
- `extractor`:
  - extract minimal useful data from a dataset
- `downloader`:
  - download and generate a dataset

## List of datasets

### 1. CVEfixes

*Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software*

**Homepage**: https://github.com/secureIT-project/CVEfixes

**Version**: `v1.0.8`

**Licence**: `CC BY 4.0`

**Included**: ✅ (Partial)
  - [`CVEfixes_java.csv`](./CVEfixes/CVEfixes_java.csv)

CVEfixes dataset is ~50 GB big.

To avoid overloading SAST tool's environment, we extract the minimal data from the dataset:
- `cve_id`: for reference only,
- `cwe_ids`: **compare** with SAST output,
- `repo_url`: download the project,
- `parents`: checkout to the vulnerable version,
- `filenames`: **compare** with SAST output.

We use Github REST API to get an estimate of the repository size:
- `repo_size`: repository size in bytes

You need to provide a Github OAuth access token because the rate limit for unauthenticated users is only `60 reqs/hour` vs `5000 reqs/hour` for authenticated users.

To generate one:
- Go to [New personal access token (classic)](https://github.com/settings/tokens/new)
- Select scopes: `repo` -> `public_repo`
- Copy the token and paste it when prompted
- Once all extraction done, delete the token

```bash
$ python3 ./datasets/CVEfixes/extract.py 
Token: ghp_************************************
Available languages
- java
Select lang: java
100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 394/394 [02:13<00:00,  2.95it/s]
Extraction completed and available at datasets/CVEfixes/CVEfixes_java.csv
```

### 2. Semgrep Test Code

*Test code for Semgrep's Community Edition and Pro rules*

**Homepage**: https://github.com/semgrep/semgrep

**Version**: `15/05/2025` (*download date*)

**Licence**: [`Semgrep Rules License v. 1.0`](https://semgrep.dev/legal/rules-license/) (*for both Community Edition and Pro*)

**Included**: ✅ (Full)
- [`Semgrep_all.json`](./SemgrepTest/Semgrep_all.json)

Community Edition rules are available [here](https://github.com/semgrep/semgrep-rules) but Pro rules are only available in Semgrep AppSec Platform (log in required).

It is possible to download rules and test codes using Semgrep API.

The provided script `downloader.py` downloads all and store in `./datasets/Semgrep/Semgrep_all.json`.

To get the token:
1. Log into your account
2. Open dev tools
3. Navigate to any pages to perform requests
4. Apply filter: `https://semgrep.dev/api`
5. Get the Bearer token from the request header

```bash
$ SEMGREP_TOKEN=YOUR_TOKEN python3 ./datasets/Semgrep/downloader.py
```

### 3. BenchmarkJava

*The OWASP Benchmark Project is a Java test suite designed to evaluate the accuracy, coverage, and speed of automated software vulnerability detection tools. Without the ability to measure these tools, it is difficult to understand their strengths and weaknesses, and compare them to each other.*

**Homepage**: https://github.com/OWASP-Benchmark/BenchmarkJava

**Version**: `v1.2`

**Licence**: `GPL-2.0`

**Included**: ✅ (Full)
  - [`BenchmarkTest*.java`](./BenchmarkJava/src/main/java/org/owasp)
  - [`expectedresults-1.2.csv`](./BenchmarkJava/expectedresults-1.2.csv)