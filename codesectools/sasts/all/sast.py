"""Defines the logic for orchestrating multiple SAST tools together."""

from typing import TYPE_CHECKING

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

        self.sasts_by_lang = {}
        self.sasts_by_dataset = {}

        for sast in self.sasts:
            for lang in sast.supported_languages:
                if self.sasts_by_lang.get(lang):
                    self.sasts_by_lang[lang].append(sast)
                else:
                    self.sasts_by_lang[lang] = [sast]

            for dataset in sast.supported_datasets:
                if self.sasts_by_dataset.get(dataset):
                    self.sasts_by_dataset[dataset].append(sast)
                else:
                    self.sasts_by_dataset[dataset] = [sast]

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
