import importlib

from sastbenchmark.datasets._base.dataset import Dataset
from sastbenchmark.utils import DATASETS_DIR

DATASETS_ALL = {}
for child in DATASETS_DIR.iterdir():
    if child.is_dir():
        if list(child.glob("dataset.py")) and child.name != "_base":
            dataset_name = child.name

            dataset_module = importlib.import_module(
                f"sastbenchmark.datasets.{dataset_name}.dataset"
            )
            dataset: Dataset = getattr(dataset_module, dataset_name)

            DATASETS_ALL[dataset_name] = dataset
