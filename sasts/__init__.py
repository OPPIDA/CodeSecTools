from sasts.Coverity.cli import CoverityCLI
from sasts.Coverity.sast import CoverityAnalysisResult, CoveritySAST
from sasts.Semgrep.cli import SemgrepCLI
from sasts.Semgrep.sast import SemgrepAnalysisResult, SemgrepSAST

SASTS_ALL = {
    CoveritySAST.name: {
        "sast": CoveritySAST,
        "analysis_result": CoverityAnalysisResult,
        "cli": CoverityCLI,
    },
    SemgrepSAST.name: {
        "sast": SemgrepSAST,
        "analysis_result": SemgrepAnalysisResult,
        "cli": SemgrepCLI,
    },
}
