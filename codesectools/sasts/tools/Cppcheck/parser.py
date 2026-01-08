"""Provides classes for parsing Cppcheck analysis results.

This module defines `CppcheckIssue` and `CppcheckAnalysisResult` to process
the XML output from a Cppcheck scan, converting it into the standardized
format used by CodeSecTools.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from codesectools.sasts.core.parser.format.SARIF.parser import SARIFAnalysisResult
from codesectools.shared.cwe import CWE, CWEs

if TYPE_CHECKING:
    from codesectools.sasts.core.parser.format.SARIF import Result


class CppcheckAnalysisResult(SARIFAnalysisResult):
    """Represent the complete result of a Cppcheck analysis."""

    sast_name = "Cppcheck"
    rule_categories = ["error", "warning", "style"]

    def get_cwe(self, result: Result, rule_id: str) -> CWE:
        """Get the CWE for a given rule ID."""
        if rule_properties := self.get_rule_properties(rule_id):
            if tags := rule_properties.tags:
                for tag in tags:
                    if m := re.search(r"cwe-(\d+)", tag.lower()):
                        cwe_id = int(m.group(1))
                        return CWEs.from_id(cwe_id)
        return CWEs.NOCWE
