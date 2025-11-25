"""Defines the JulietTestSuiteC dataset for evaluating SAST tools on C code.

This module provides the classes and logic to load the Juliet Test Suite for C/C++,
which consists of C test files with known vulnerabilities. It downloads the source code
from the NIST Software Assurance Reference Dataset (SARD) and parses an XML manifest
to associate test files with expected results.
"""

import io
import re
import shutil
import zipfile
from pathlib import Path
from typing import Self

from codesectools.datasets.core.dataset import File, PrebuiltFileDataset
from codesectools.shared.cwe import CWE, CWEs
from codesectools.utils import CPU_COUNT


class TestCode(File):
    """Represents a single test file in the JulietTestSuiteC dataset."""

    def __init__(
        self,
        filepath: Path,
        content: str | bytes,
        cwes: list[CWE],
        has_vuln: bool,
    ) -> None:
        """Initialize a TestCode instance.

        Args:
            filepath: The path to the file.
            content: The content of the file, as a string or bytes.
            cwes: A list of CWEs associated with the file.
            has_vuln: A boolean indicating if the vulnerability is real or a false positive test case.

        """
        super().__init__(
            filepath=filepath, content=content, cwes=cwes, has_vuln=has_vuln
        )


class JulietTestSuiteC(PrebuiltFileDataset):
    """Represents the Juliet Test Suite for C/C++.

    This class handles downloading, extracting, and loading the C/C++ test cases
    from the Juliet Test Suite.
    """

    name = "JulietTestSuiteC"
    supported_languages = ["c"]
    license = "CC0 1.0 Universal"
    license_url = "https://data.niaid.nih.gov/resources?id=zenodo_4701386#description"

    build_command = f"bear -- make -C ./C individuals -j{CPU_COUNT}"
    prebuilt_expected = (Path("."), "compile_commands.json")
    artifacts_arg = "compile_commands.json"

    def __init__(self, lang: None | str = None) -> None:
        """Initialize the JulietTestSuiteC dataset.

        Args:
            lang: The programming language of the dataset files.
                Must be one of the supported languages.

        """
        super().__init__(lang)

    def __eq__(self, other: str | Self) -> bool:
        """Compare this dataset with another object for equality.

        Args:
            other: The object to compare with. Can be a string (dataset name)
                   or another JulietTestSuiteC instance.

        Returns:
            True if the names are equal, False otherwise.

        """
        if isinstance(other, str):
            return self.name == other
        elif isinstance(other, self.__class__):
            return self.name == other.name
        else:
            return False

    def download_files(self: Self, test: bool = False) -> None:
        """Download and extract the dataset from the NIST SARD website.

        Downloads the zip archive, extracts its contents, and prunes the test cases
        to a smaller subset for faster processing. If in test mode, it further
        reduces the dataset to only a single CWE.

        Args:
            test: If True, reduce the number of test files for faster testing.

        """
        import requests

        zip_file = io.BytesIO(
            requests.get(
                "https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"
            ).content
        )
        with zipfile.ZipFile(zip_file, "r") as zip_ref:
            zip_ref.extractall(self.directory)

        # Limit to one set for each CWE
        testcases = self.directory / "C" / "testcases"
        for set_dir in testcases.glob("CWE*/s*"):
            if set_dir.name != "s01":
                shutil.move(set_dir, set_dir.parent / f"_{set_dir.name}")

        if test:
            for cwe_dir in list(testcases.glob("CWE*")):
                if not cwe_dir.name.startswith("CWE835"):
                    shutil.rmtree(cwe_dir)

    def load_dataset(self) -> list[TestCode]:
        """Load the JulietTestSuiteC dataset from the source files.

        Parses the `manifest.xml` file to identify vulnerabilities in the C/C++
        source files and creates a `TestCode` object for each file containing a flaw.

        Returns:
            A list of `TestCode` objects representing the dataset.

        """
        from lxml import etree

        files = []
        testcode_dir = self.directory / "C" / "testcases"
        testcode_paths = {
            path.name: path
            for path in list(testcode_dir.rglob("CWE*.c"))
            + list(testcode_dir.rglob("CWE*.cpp"))
        }
        manifest_path = self.directory / "C" / "manifest.xml"
        manifest = etree.parse(manifest_path)
        testcases = manifest.xpath("/container/testcase")
        for testcase in testcases:
            files_tree = testcase.xpath("file")
            for file_tree in files_tree:
                file_path = file_tree.get("path")
                if file_obj := testcode_paths.get(file_path):
                    if file_tree.xpath("flaw"):
                        flaw = file_tree.xpath("flaw")[0]
                        flaw_name = flaw.get("name")
                        if m := re.search(r"CWE-(\d+)", flaw_name):
                            cwe_id = int(m.group(1))
                            files.append(
                                TestCode(
                                    filepath=file_obj.relative_to(self.directory),
                                    content=file_obj.read_bytes(),
                                    cwes=[CWEs.from_id(cwe_id)],
                                    has_vuln=True,
                                )
                            )
        return files
