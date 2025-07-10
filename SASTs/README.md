# SAST

- [SAST](#sast)
  - [Overview](#overview)
  - [SAST components](#sast-components)
  - [List of SASTs](#list-of-sasts)
    - [1. Coverity Static Analysis](#1-coverity-static-analysis)

## Overview
- We only use the `security` preset of each tool.
- We mainly evaluate if the SAST can find the vulnerabilities.

## SAST components
*None of them are mandatory; they are provided solely as templates*

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

### 1. Coverity Static Analysis

*The most trusted solution for finding code quality defects in large-scale, complex software*

**Homepage**: https://www.blackduck.com/static-analysis-tools-sast/coverity.html

**Licence**: `Commercial` (*Consequently, the analysis results are omitted*)

**Included**: ❌ (Existing installation needed)

**Note**: 
- For benchmarking, Coverity is only used in **buildless** mode to automate the process
- For the wrapper, Coverity needs the source code to be compiled