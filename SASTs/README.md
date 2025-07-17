# SAST

- [SAST](#sast)
  - [Overview](#overview)
  - [SAST components](#sast-components)
  - [List of SASTs](#list-of-sasts)
    - [1. Coverity Static Analysis](#1-coverity-static-analysis)
    - [2. Semgrep Pro Engine](#2-semgrep-pro-engine)

## Overview
- We use only the default security configurations provided by each tool, without any custom settings.

## SAST components
*None of them are mandatory; they are provided solely as templates*

- `analyzer`: 
  - analyze project with the SAST
  - save SAST results (SAST's own format)
- `parser`:
  - aggregate and process results
  - process result to a common format (see [./_base/parser.py](./_base/parser.py))
  - generate plots for visualization
- `wrapper`:
  - assist with SAST CLI tools for manual analysis
- `constants`:
  - Variables used very often 
- `cli`:
  - define cli commands

## List of SASTs

### 1. Coverity Static Analysis

*The most trusted solution for finding code quality defects in large-scale, complex software*

**Homepage**: https://www.blackduck.com/static-analysis-tools-sast/coverity.html

**Version**: `2024.12.1`

**Licence**: `Commercial` ([Terms of Service](https://www.blackduck.com/company/legal/terms-of-service.html))

**Overview**:
- ❌ The tool is not freely available and requires a commercial license
- ❌ Sharing of analysis results is not permitted

**Configuration**:
- General security: `--all-security`

**Note**:
- For benchmarking, Coverity is only used in **buildless** mode to automate the process
- For the wrapper, Coverity **compiles** the source code

### 2. Semgrep Pro Engine

*Lightweight static analysis for many languages. Find bug variants with patterns that look like source code.*

**Homepage**: https://semgrep.dev/

**Version**: `1.128.1`

**Licence**: [`Semgrep Rules License v. 1.0`](https://semgrep.dev/legal/rules-license/)

**Overview**:
- ✅ The tool is free to use under the terms of its license
- ✅ Sharing of analysis results is permitted

**Configuration**:
- Language specific: `--config "p/LANG"`

**Note**: 
- A Semgrep account is needed to access pro engine and pro rules
- An internet connexion is required
- Semgrep Pro Engine needs to be installed:
  ```bash
  # Pro engine requires users to be logged in
  semgrep login
  semgrep install-semgrep-pro

  # Scan using Pro engine with --pro
  semgrep scan --config="p/java" --pro --metrics=off
  ```