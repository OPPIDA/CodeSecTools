# CodeSecTools

<div align="center">
  <img src="docs/assets/logo.svg" alt="Logo" style="width: 200px; height: auto;" />
</div>

A framework for code security that provides abstractions for static analysis tools and datasets to support their integration, testing, and evaluation.

## Overview

**CodeSecTools** is a collection of scripts and wrappers that abstract external resources (such as SASTs, datasets, and codebases), providing standardized interfaces to help them interact easily.

<div align="center">
  <img src="docs/assets/overview.svg" alt="Logo" style="width: auto; height: auto;" />
</div>

## Installation
  
```bash
pip install .
```
## Usage

- CLI command:

  ```bash
  cstools
  ```

- Python module:

  ```python
  from pathlib import Path
  from codesectools.sasts.SemgrepCE.sast import SemgrepCESAST
  my_sast = SemgrepCESAST()
  my_sast.run_analysis(
      lang="java", 
      project_dir=Path("my_project"), 
      output_dir=Path("/tmp/out")
  )
  # Results are saved in /tmp/out

  print(list(Path("/tmp/out").rglob("*")))
  # [PosixPath('/tmp/out/cstools_output.json'), PosixPath('/tmp/out/semgrep_output.json')]
  ```

  For more information, check the [API Reference](https://oppida.github.io/CodeSecTools/api/index.html)

## Documentation

The documentation is available [online](https://oppida.github.io/CodeSecTools/).

Or, you can build it locally:
```bash
pip install .[docs]
mkdocs serve
```

## Disclaimer

This project provides wrappers and scripts to integrate with various third-party static analysis security testing (SAST) tools and datasets. It is important to note that this project does not include these third-party tools or datasets, unless otherwise specified. When a tool or dataset is included, its associated license file is also provided.

Users of this project are solely responsible for reviewing, understanding, and complying with the licenses and terms of use associated with any third-party tools or datasets they choose to use through this framework. The respective licenses and terms can be found on the official websites or in the documentation of each tool or dataset.