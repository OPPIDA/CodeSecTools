# CATBenchmark - Code Analysis Tools Benchmark

Collection of Code Analysis Tools and dataset

Structure:

For each tool, there are:
- analyzer:
    - generic functions:
        - download vulnerable project
        - build project (when cannot be avoided)
        - analyze project
        - save results
        - import results from analysis already done
    - script to run on EACH dataset
- parser:
    - generic functions:
        - tools results processor and aggregator (multiple result files to one)
        - epxort to JSON
        - generate bar chart (sort by files, checkers, cwe)
    - confusion matrix for EACH dataset
- wrapper (only for user interaction):
    - generic functions:
        - setup
        - build
        - capture
        - analyze
For dev only:
- constants:
    - values predefined for the tools (checkers, supported lang)
- main (CLI setup):
    - analyze
    - parse
    - wrapper