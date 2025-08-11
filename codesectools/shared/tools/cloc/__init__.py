import json
from pathlib import Path

from codesectools.utils import SHARED_DIR, run_command


def cloc_get_loc(
    dir: Path, lang: str, include: str | None = None, exclude: str | None = None
) -> int:
    to_cloc_name = {"java": "Java"}
    command = ["perl", SHARED_DIR / "tools" / "cloc.pl", ".", "--json"]
    command.append(f"--include-lang={to_cloc_name[lang]}")
    _, out = run_command(command, dir)
    json_out = json.loads(out)
    return json_out[to_cloc_name[lang]]["code"]
