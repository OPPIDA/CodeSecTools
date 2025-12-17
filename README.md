<!--start-include-->
# CodeSecTools <!-- omit in toc -->

<div align="center">
  <img src="docs/assets/logo.svg" alt="Logo" style="width: 200px; height: auto;" />
</div>

A framework for code security that provides abstractions for static analysis tools and datasets to support their integration, testing, and evaluation.
<!--end-include-->

## Table Of Contents <!-- omit in toc -->
- [Overview](#overview)
- [Features](#features)
- [SAST Tool Integration Status](#sast-tool-integration-status)
- [Usage](#usage)
    - [Command-line interface](#command-line-interface)
    - [Docker](#docker)
    - [Python API](#python-api)

<!--start-include-->
## Overview

**CodeSecTools** is a collection of scripts and wrappers that abstract external resources (such as SAST tools, datasets, and codebases), providing standardized interfaces to help them interact easily.

<div align="center">
  <img src="docs/assets/overview.svg" alt="CodeSecTools Overview" style="width: 75%; height: auto;" />
</div>

For step-by-step instructions on installation, configuration, and basic usage, please refer to the [quick start guide](https://oppida.github.io/CodeSecTools/home/quick_start_guide.html).

For more details on the design and integration of SAST tools and datasets in CodeSecTools, please refer to the [documentation](https://oppida.github.io/CodeSecTools). 

## Features

- **Standardized SAST Tool Integration**: Provides a common abstraction layer for integrating various SAST tools. Once a tool is integrated, it automatically benefits from the framework’s core functionalities.
- **Unified Dataset Integration**: Uses a similar abstraction for handling datasets, allowing for consistent benchmarking of SAST tools across different sets of codebases, whether they are collections of individual files or entire Git repositories.
- **Project Analysis and Benchmarking**: Users can analyze their own projects or benchmark SAST tools against curated datasets to evaluate their effectiveness, including metrics like true positives, false positives, and false negatives.
- **Concurrent Analysis for Cross-Verification**: CodeSecTools can run multiple SAST tools simultaneously on the same project. This allows for the aggregation and cross-verification of results, increasing confidence in the identified vulnerabilities by highlighting findings reported by multiple tools.
- **Automated Reporting and Visualization**: The framework can generate detailed reports in HTML format and create graphs to visualize analysis results, helping to identify trends such as the most common CWEs or the files with the highest number of defects.

> [!WARNING]
> This project provides wrappers and scripts to integrate with various third-party static analysis security testing (SAST) tools and datasets. By default, this project **does not include third-party tools or datasets**. In the few instances where they are included, their associated license files are provided.
> 
> Users of this project are solely responsible for reviewing, understanding, and complying with the licenses and terms of use associated with any third-party tools or datasets they choose to use through this framework. The respective licenses and terms can be found on the official websites or in the documentation of each tool or dataset.

## SAST Tool Integration Status

|SAST Tool|Languages|Maintained|Continuous Testing|Last Test Date|
|:---:|:---:|:---:|:---:|:---:|
|Coverity|Java|⚠️<br>(Deprioritized)|❌<br>(Proprietary)|October 2025|
|Semgrep Community Edition|C/C++, Java|✅|✅|[Latest PR](https://github.com/OPPIDA/CodeSecTools/actions/workflows/ci.yaml)|
|Snyk Code|C/C++, Java|✅|❌<br>(Rate limited)|November 2025|
|Bearer|Java|✅|✅|[Latest PR](https://github.com/OPPIDA/CodeSecTools/actions/workflows/ci.yaml)|
|SpotBugs|Java|✅|✅|[Latest PR](https://github.com/OPPIDA/CodeSecTools/actions/workflows/ci.yaml)|
|Cppcheck|C/C++|✅|✅|[Latest PR](https://github.com/OPPIDA/CodeSecTools/actions/workflows/ci.yaml)|

## Usage

#### Command-line interface

```bash
$ cstools
                                                                                                                                                                   
 Usage: cstools [OPTIONS] COMMAND [ARGS]...                                                                                                                        
                                                                                                                                                                   
 CodeSecTools CLI.                                                                                                                                                 
                                                                                                                                                                   
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --debug               -d        Show debugging messages and disable pretty exceptions.                                                                          │
│ --version             -v        Show the tool's version.                                                                                                        │
│ --install-completion            Install completion for the current shell.                                                                                       │
│ --show-completion               Show completion for the current shell, to copy it or customize the installation.                                                │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ status      Display the availability of SAST tools and datasets.                                                                                                │
│ allsast     Run all available SAST tools together.                                                                                                              │
│ bearer      Bearer SAST                                                                                                                                         │
│ coverity    Coverity Static Analysis                                                                                                                            │
│ cppcheck    Cppcheck                                                                                                                                            │
│ semgrepce   Semgrep Community Edition Engine                                                                                                                    │
│ snykcode    Snyk Code                                                                                                                                           │
│ spotbugs    SpotBugs                                                                                                                                            │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

#### Docker

A Docker image is available with only free and offline SAST tools pre-installed.

```bash
UID=$(id -u) GID=$(id -g) docker compose build main
docker run -it -v $HOME/.codesectools:/home/codesectools/.codesectools codesectools /bin/bash
```

Mount necessary directories if you want to include:

- a target (`-v ./myproject:/home/codesectools/myproject`)
- existing CodeSecTools data (`-v $HOME/.codesectools:/home/codesectools/.codesectools`) 

A better way is to use the CLI:

```bash
$ cstools -d docker --help
                                                                                                                                                                   
 Usage: cstools docker [OPTIONS]                                                                                                                                   
                                                                                                                                                                   
 Start the Docker environment for the specified target (current directory by default).                                                                             
                                                                                                                                                                   
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --target                         PATH  The directory to mount inside the container. [default: .]                                                                │
│ --isolation    --no-isolation          Enable network isolation for the container (disables host network sharing). [default: no-isolation]                      │
│ --help                                 Show this message and exit.                                                                                              │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

```

#### Python API

```python
from pathlib import Path

from codesectools.sasts.core.graphics import ProjectGraphics
from codesectools.sasts.tools.SemgrepCE.parser import SemgrepCEAnalysisResult
from codesectools.sasts.tools.SemgrepCE.sast import SemgrepCESAST

project_dir = Path("path/to/project")
output_dir = Path("path/to/project")

# Run SAST Tool
sast = SemgrepCESAST()
sast.run_analysis(lang="java", project_dir=project_dir, output_dir=output_dir)

# Parse results
parser = SemgrepCEAnalysisResult.load_from_output_dir(output_dir=output_dir)
print(parser.stats_by_categories())
print(parser.stats_by_checkers())
print(parser.stats_by_cwes())
print(parser.stats_by_files())

# Visualize results
graphics = ProjectGraphics(sast=sast, project_name=project_dir.name)
for plot_function in graphics.plot_functions:
    fig = plot_function()
    fig.show()
```
<!--end-include-->