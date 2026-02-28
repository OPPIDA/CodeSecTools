"""Provides classes for parsing Snyk Code analysis results.

This module defines `SnykCodeIssue` and `SnykCodeAnalysisResult` to process
the SARIF JSON output from a Snyk Code scan, converting it into the standardized
format used by CodeSecTools.
"""

import re

from codesectools.sasts.core.parser.format.SARIF import Result
from codesectools.sasts.core.parser.format.SARIF.parser import SARIFAnalysisResult
from codesectools.shared.cwe import CWE, CWEs


class SnykCodeAnalysisResult(SARIFAnalysisResult):
    """Represent the complete result of a Snyk Code analysis from a SARIF file."""

    sast_name = "SnykCode"
    rule_categories = []

    def get_cwe(self, result: Result, rule_id: str) -> CWE:
        """Get the CWE for a given rule ID."""
        if rule_properties := self.get_rule_properties(rule_id):
            if extra := rule_properties.__pydantic_extra__:
                if cwe := extra.get("cwe"):
                    if m := re.search(r"cwe-(\d+)", cwe[0].lower()):
                        cwe_id = int(m.group(1))
                        return CWEs.from_id(cwe_id)
        return CWEs.NOCWE
