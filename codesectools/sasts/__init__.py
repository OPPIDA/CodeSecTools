import importlib

from click import Group

from codesectools.sasts.core.sast import SAST, AnalysisResult
from codesectools.utils import SASTS_DIR

SASTS_ALL = {}
for child in SASTS_DIR.iterdir():
    if child.is_dir():
        if list(child.glob("sast.py")) and child.name != "core":
            sast_name = child.name

            sast_module = importlib.import_module(
                f"codesectools.sasts.{sast_name}.sast"
            )
            sast: SAST = getattr(sast_module, f"{sast_name}SAST")
            analysis_result: AnalysisResult = getattr(
                sast_module, f"{sast_name}AnalysisResult"
            )

            cli_module = importlib.import_module(f"codesectools.sasts.{sast_name}.cli")
            cli: Group = getattr(cli_module, f"{sast_name}CLI")

            SASTS_ALL[sast_name] = {
                "sast": sast,
                "analysis_result": analysis_result,
                "cli": cli,
            }
