"""Provides a function to count lines of code using the cloc tool.

This module contains a wrapper around the `cloc.pl` Perl script to calculate
the number of physical lines of source code for a specific language within
a directory.
"""

import json
from pathlib import Path

from codesectools.utils import SHARED_DIR, run_command


def cloc_get_loc(
    dir: Path, lang: str, include: str | None = None, exclude: str | None = None
) -> int:
    """Get the lines of code for a specific language in a directory.

    Args:
        dir: The directory to analyze.
        lang: The language to count (e.g., "java").
        include: A pattern for files to include (not currently used).
        exclude: A pattern for files to exclude (not currently used).

    Returns:
        The number of physical lines of code for the specified language.

    """
    to_cloc_name = {"java": "Java"}
    command = ["perl", SHARED_DIR / "tools" / "cloc.pl", ".", "--json"]
    command.append(f"--include-lang={to_cloc_name[lang]}")
    _, out = run_command(command, dir)
    json_out = json.loads(out)
    return json_out[to_cloc_name[lang]]["code"]
