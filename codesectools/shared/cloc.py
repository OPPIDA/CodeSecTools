"""Provide a wrapper for counting lines of code using the cloc tool.

This module contains the `Cloc` class, a wrapper around the `cloc` tool,
to calculate the number of physical lines of source code for a specific
language within a directory.
"""

import json
import shutil
from pathlib import Path

import git

from codesectools.utils import USER_CACHE_DIR, MissingFile, NonZeroExit, run_command


class Cloc:
    """A wrapper for the 'cloc' (Count Lines of Code) tool.

    Find the 'cloc' executable or download and use the Perl script if the
    executable is not available but Perl is. Provide a method to count
    lines of code for a specific language.

    Attributes:
        version (str): The version of the cloc Perl script to download.
        cloc_names (dict): A mapping from internal language names to the names
            used by cloc.
        dir (Path): The directory to run cloc in.
        lang (str): The programming language to count, mapped to the cloc name.
        base_command (list[str]): The command list to execute cloc.

    """

    version = "2.06"
    cloc_names = {"java": "Java", "c": "C"}

    def __init__(self, dir: Path, lang: str) -> None:
        """Initialize the Cloc wrapper.

        Check for the 'cloc' binary. If not found, check for 'perl' and
        download the 'cloc.pl' script if it doesn't exist locally.

        Args:
            dir: The directory to run cloc in.
            lang: The programming language to count.

        """
        self.dir = dir
        self.lang = self.cloc_names[lang]
        if shutil.which("cloc"):
            self.base_command = ["cloc", ".", "--json"]
        else:
            if shutil.which("perl"):
                cloc_repo = USER_CACHE_DIR / "cloc"
                if not cloc_repo.is_dir():
                    repo = git.Repo.clone_from(
                        "https://github.com/AlDanial/cloc.git",
                        cloc_repo,
                        depth=1,
                        sparse=True,
                        filter=["tree:0"],
                    )
                    repo.git.sparse_checkout(
                        "set",
                        "--no-cone",
                        *[
                            "cloc",
                            "LICENSE",
                        ],
                    )
                self.base_command = [
                    "perl",
                    str(USER_CACHE_DIR / "cloc" / "cloc"),
                    ".",
                    "--json",
                ]
            else:
                raise MissingFile(["perl", "cloc"])

    def get_loc(self) -> int:
        """Get the lines of code for the specified language.

        Execute the cloc command, parse the JSON output, and return the
        number of source code lines.

        Returns:
            The number of lines of code, or 0 if the language is not found
            in the output.

        Raises:
            NonZeroExit: If the cloc command fails.

        """
        full_command = self.base_command + [f"--include-lang={self.lang}"]
        retcode, out = run_command(full_command, self.dir)
        if retcode != 0:
            raise NonZeroExit(full_command, out)
        json_out = json.loads(out)
        if lang_stats := json_out.get(self.lang):
            return lang_stats["code"]
        else:
            return 0
