# SAST

## Overview
- We only use the `security` preset of each tool.
- We mainly evaluate if the SAST can find the vulnerabilities.

## SAST components
- `analyzer`: 
  - analyze project with the SAST
  - save SAST results (SAST's own format)
- `parser`:
  - aggregate and process results
  - export results to a unified format (JSON)
  - export results to be compared with datasets
  - generate plots for visualization
- `wrapper`:
  - assist with SAST CLI tools
- `constants`:
  - security checkers
  - supported languages
- `main`:
  - CLI entry point

## List of SASTs

### 1. [Coverity Static Analysis](./Coverity/)

*The most trusted solution for finding code quality defects in large-scale, complex software*

[Homepage - Black Duck](https://www.blackduck.com/static-analysis-tools-sast/coverity.html)

License: `Commercial`