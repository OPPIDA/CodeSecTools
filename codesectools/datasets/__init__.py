"""Dynamically discovers and registers all available datasets.

This module iterates through the subdirectories of the `codesectools/datasets`
directory. For each subdirectory that represents a dataset (i.e., contains a
`dataset.py` file and is not the `core` directory), it dynamically imports
the dataset module and adds the dataset class to the `DATASETS_ALL` dictionary.

Attributes:
    DATASETS_ALL (dict): A dictionary mapping dataset names to their
        corresponding metadata, including the dataset class and its cache status.

"""

import importlib

from codesectools.datasets.core.dataset import Dataset
from codesectools.utils import DATASETS_DIR

DATASETS_ALL = {}
for child in DATASETS_DIR.iterdir():
    if child.is_dir():
        if list(child.glob("dataset.py")) and child.name != "core":
            dataset_name = child.name

            dataset_module = importlib.import_module(
                f"codesectools.datasets.{dataset_name}.dataset"
            )
            dataset: Dataset = getattr(dataset_module, dataset_name)

            DATASETS_ALL[dataset_name] = {
                "cached": dataset.is_cached(),
                "dataset": dataset,
            }

DATASETS_ALL = dict(sorted(DATASETS_ALL.items()))
