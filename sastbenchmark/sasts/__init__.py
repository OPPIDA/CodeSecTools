from sastbenchmark.sasts.Coverity.cli import CoverityCLI
from sastbenchmark.sasts.Coverity.sast import CoverityAnalysisResult, CoveritySAST
from sastbenchmark.sasts.Semgrep.cli import SemgrepCLI
from sastbenchmark.sasts.Semgrep.sast import SemgrepAnalysisResult, SemgrepSAST

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
