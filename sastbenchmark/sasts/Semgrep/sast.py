from pathlib import Path

from sastbenchmark.sasts._core.sast import SAST
from sastbenchmark.sasts.Semgrep.constants import (
    COLOR_MAPPING,
    LANG,
    SUPPORTED_DATASETS,
)
from sastbenchmark.sasts.Semgrep.parser import SemgrepAnalysisResult


class SemgrepSAST(SAST):
    name = "Semgrep"

    def __init__(self) -> None:
        super().__init__(
            commands=[
                "semgrep scan --config=p/{lang} --pro --metrics=off --json-output=output.json --jobs=4".split(
                    " "
                )
            ],
            analysis_files=[(Path("analysis.log"), True), (Path("output.json"), True)],
            parser=SemgrepAnalysisResult,
            supported_languages=LANG.keys(),
            supported_datasets=SUPPORTED_DATASETS,
            color_mapping=COLOR_MAPPING,
        )
