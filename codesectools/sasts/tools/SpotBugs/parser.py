"""Provides classes for parsing SpotBugs analysis results.

This module defines `SpotBugsIssue` and `SpotBugsAnalysisResult` to process
the SARIF JSON output from a SpotBugs scan, converting it into the standardized
format used by CodeSecTools.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from codesectools.sasts.core.parser.format.SARIF.parser import SARIFAnalysisResult
from codesectools.shared.cwe import CWE, CWEs

if TYPE_CHECKING:
    from codesectools.sasts.core.parser.format.SARIF import Result


class SpotBugsAnalysisResult(SARIFAnalysisResult):
    """Represent the complete result of a SpotBugs analysis."""

    sast_name = "SpotBugs"
    rule_categories = ["SECURITY", "CORRECTNESS", "MT_CORRECTNESS"]

    # uri is Java class name which misses base project path:
    # org/mypackage/...
    # We want:
    # /home/user/mypackage/src/main/java/org/mypackage/...
    def patch_dict(self, sarif_dict: dict) -> dict:
        """Patch the SARIF dictionary to resolve relative Java class paths."""
        partial_parents = {}

        def recursive_patch(data: Any) -> None:  # noqa: ANN401
            if isinstance(data, dict):
                for key, value in data.items():
                    if key == "uri":
                        partial_filepath = Path(value)
                        if partial_filepath.parent not in partial_parents:
                            if next(
                                self.source_path.rglob(str(partial_filepath)), None
                            ):
                                filepath = next(
                                    self.source_path.rglob(str(partial_filepath))
                                ).relative_to(self.source_path)
                                partial_parents[partial_filepath.parent] = (
                                    filepath.parent
                                )
                        else:
                            filepath = (
                                partial_parents[partial_filepath.parent]
                                / partial_filepath.name
                            )

                        data[key] = str(filepath)
                    else:
                        recursive_patch(value)

            elif isinstance(data, list):
                for item in data:
                    recursive_patch(item)

        recursive_patch(sarif_dict)
        self.save_patched_dict(sarif_dict)
        return sarif_dict

    def get_cwe(self, result: Result, rule_id: str) -> CWE:
        """Get the CWE for a given rule ID."""
        rule = self.rules[rule_id]
        if relationships := rule.relationships:
            for relationship in relationships:
                if target := relationship.target:
                    if root := target.root:
                        if id := root.id:
                            return CWEs.from_id(int(id))
        return CWEs.NOCWE
