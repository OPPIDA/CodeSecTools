from sasts._base.sast import SAST
from sasts.Semgrep.constants import COLOR_MAPPING, LANG, SUPPORTED_DATASETS
from sasts.Semgrep.parser import SemgrepAnalysisResult


class SemgrepSAST(SAST):
    name = "Semgrep"

    def __init__(self):
        super().__init__(
            commands=[
                "semgrep scan --config=p/{lang} --pro --metrics=off --json-output=output.json --jobs=4".split(
                    " "
                )
            ],
            analysis_files=[("analysis.log", True), ("output.json", True)],
            parser=SemgrepAnalysisResult,
            supported_languages=LANG.keys(),
            supported_datasets=SUPPORTED_DATASETS,
            color_mapping=COLOR_MAPPING,
        )
