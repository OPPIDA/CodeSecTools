# CodeSecTools

<div align="center">
  <img src="docs/assets/logo.svg" alt="Logo" style="width: 200px; height: auto;" />
</div>

A framework for code security that provides abstractions for static analysis tools and datasets to support their integration, testing, and evaluation.

## Overview

**CodeSecTools** is a collection of scripts and wrappers that abstract external resources (such as SASTs, datasets, and codebases), providing standardized interfaces to help them interact easily.

<div align="center">
  <img src="docs/assets/overview.svg" alt="CoseSecTools Overview" style="width: auto; height: auto;" />
</div>

> [!WARNING]
> This project provides wrappers and scripts to integrate with various third-party static analysis security testing (SAST) tools and datasets. It is important to note that this project **does not include** these third-party tools or datasets, unless otherwise specified. When a tool or dataset is included, its associated license file is also provided.
> 
> Users of this project are solely responsible for reviewing, understanding, and complying with the licenses and terms of use associated with any third-party tools or datasets they choose to use through this framework. The respective licenses and terms can be found on the official websites or in the documentation of each tool or dataset.


## Installation
  
```bash
git clone git@github.com:OPPIDA/CodeSecTools.git
cd CodeSecTools
pip install .
```
## Usage

<!-- termynal -->
```console
$ cstools
                                                                       
 Usage: cstools [OPTIONS] COMMAND [ARGS]...                            
                                                                       
 CodeSecTools: A framework for code security that provides             
 abstractions for static analysis tools and datasets to support their  
 integration, testing, and evaluation.                                 
                                                                       
╭─ Options ───────────────────────────────────────────────────────────╮
│ --debug               -d        Show debugging messages             │
│ --version             -v        Show the tool's version.            │
│ --install-completion            Install completion for the current  │
│                                 shell.                              │
│ --show-completion               Show completion for the current     │
│                                 shell, to copy it or customize the  │
│                                 installation.                       │
│ --help                          Show this message and exit.         │
╰─────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────╮
│ status      Display the availability of SASTs and datasets.         │
│ allsast     Run all available SASTs together.                       │
│ bearer      Bearer SAST                                             │
│ coverity    Coverity Static Analysis                                │
│ semgrepce   Semgrep Community Edition Engine                        │
│ snykcode    Snyk Code                                               │
╰─────────────────────────────────────────────────────────────────────╯
```

## Documentation

The documentation is available [online](https://oppida.github.io/CodeSecTools/).

Or, you can build it locally:
```bash
pip install .[docs]
mkdocs serve
```