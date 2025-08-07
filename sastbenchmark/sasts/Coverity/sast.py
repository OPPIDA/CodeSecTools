from pathlib import Path

from sastbenchmark.sasts._base.sast import SAST
from sastbenchmark.sasts.Coverity.constants import (
    COLOR_MAPPING,
    LANG,
    SUPPORTED_DATASETS,
)
from sastbenchmark.sasts.Coverity.parser import CoverityAnalysisResult


class CoveritySAST(SAST):
    name = "Coverity"

    def __init__(self) -> None:
        super().__init__(
            commands=[
                "coverity capture --disable-build-command-inference --language {lang}".split(
                    " "
                ),
                "cov-analyze --dir idir --all-security --enable-callgraph-metrics".split(
                    " "
                ),
            ],
            analysis_files=[
                (Path("coverity.yaml"), False),
                (Path("idir", "coverity-cli", "capture-files-src-list*"), True),
                (Path("idir", "output", "*.xml"), False),
            ],
            parser=CoverityAnalysisResult,
            supported_languages=LANG.keys(),
            supported_datasets=SUPPORTED_DATASETS,
            color_mapping=COLOR_MAPPING,
        )
