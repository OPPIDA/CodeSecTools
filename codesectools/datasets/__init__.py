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
from typing import Any

from codesectools.datasets.core.dataset import Dataset
from codesectools.utils import DATASETS_DIR


class LazyDatasetLoader:
    """Lazily load a dataset class to avoid premature imports."""

    def __init__(self, name: str) -> None:
        """Initialize the lazy loader.

        Args:
            name: The name of the dataset to load.

        """
        self.name = name
        self.loaded = False

    def _load(self) -> None:
        """Import the dataset module and class on first access."""
        if not self.loaded:
            self.dataset_module = importlib.import_module(
                f"codesectools.datasets.{self.name}.dataset"
            )
            self.dataset: Dataset = getattr(self.dataset_module, self.name)

            self.loaded = True

    def __call__(self, *args: Any, **kwargs: Any) -> Dataset:
        """Create an instance of the loaded dataset class."""
        self._load()
        return self.dataset(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:  # noqa: ANN401
        """Proxy attribute access to the loaded dataset class."""
        self._load()
        return getattr(self.dataset, name)


DATASETS_ALL = {}
for child in DATASETS_DIR.iterdir():
    if child.is_dir():
        if list(child.glob("dataset.py")) and child.name != "core":
            dataset_name = child.name

            DATASETS_ALL[dataset_name] = LazyDatasetLoader(dataset_name)

DATASETS_ALL = dict(sorted(DATASETS_ALL.items()))
