"""Defines the logic for orchestrating multiple SAST tools together."""

from typing import TYPE_CHECKING

from codesectools.datasets import DATASETS_ALL
from codesectools.sasts import SASTS_ALL
from codesectools.sasts.all.parser import AllSASTAnalysisResult
from codesectools.utils import USER_OUTPUT_DIR

if TYPE_CHECKING:
    from codesectools.sasts.core.sast import SAST


class AllSAST:
    """Orchestrate running multiple SAST tools and managing their combined results."""

    name = "AllSAST"
    parser = AllSASTAnalysisResult

    def __init__(self) -> None:
        """Initialize the AllSAST instance."""
        self.output_dir = USER_OUTPUT_DIR / self.name
        self.sasts: list[SAST] = []
        for _, sast_data in SASTS_ALL.items():
            if sast_data["status"] == "full":
                self.sasts.append(sast_data["sast"]())

        self.supported_languages = {}
        self.supported_dataset_names = {}

        for sast in self.sasts:
            if not self.supported_languages:
                self.supported_languages = set(sast.supported_languages)
                self.supported_dataset_names = set(sast.supported_dataset_names)
            else:
                self.supported_languages &= set(sast.supported_languages)
                self.supported_dataset_names &= set(sast.supported_dataset_names)

        self.supported_datasets = [
            DATASETS_ALL[d] for d in self.supported_dataset_names
        ]

    @property
    def supported_dataset_full_names(self) -> set[str]:
        """List all language-specific datasets supported by all enabled SAST tools."""
        datasets_full_name = set()
        for dataset in self.supported_datasets:
            for dataset_full_name in dataset.list_dataset_full_names():
                dataset_name, lang = dataset_full_name.split("_")
                if lang in self.supported_languages:
                    datasets_full_name.add(dataset_full_name)
        return datasets_full_name

    def list_results(
        self, project: bool = False, dataset: bool = False, limit: int | None = None
    ) -> set[str]:
        """List the names of analysis results common to all enabled SAST tools."""
        output_dirs = set()
        for sast in self.sasts:
            if not output_dirs:
                output_dirs = set(
                    sast.list_results(project=project, dataset=dataset, limit=limit)
                )
            else:
                output_dirs |= set(
                    sast.list_results(project=project, dataset=dataset, limit=limit)
                )
        return output_dirs
