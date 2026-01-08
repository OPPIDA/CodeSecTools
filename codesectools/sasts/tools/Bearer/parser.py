"""Provide classes for parsing Bearer analysis results.

This module defines `BearerFinding` and `BearerAnalysisResult` to process
the JSON output from a Bearer scan, converting it into the standardized
format used by CodeSecTools.
"""

from itertools import chain

import yaml

from codesectools.sasts.core.parser.format.SARIF import Result
from codesectools.sasts.core.parser.format.SARIF.parser import SARIFAnalysisResult
from codesectools.shared.cwe import CWE, CWEs
from codesectools.utils import USER_CACHE_DIR

BEARER_RULES_DIR = USER_CACHE_DIR / "bearer-rules" / "rules"


class BearerAnalysisResult(SARIFAnalysisResult):
    """Represent the complete result of a Bearer analysis from a SARIF file."""

    sast_name = "Bearer"

    @staticmethod
    # @Cache(BEARER_RULES_DIR / ".cstools_cache").memoize(expire=None)
    def get_raw_rules() -> dict:
        """Load and return all Bearer rules from the cached YAML files."""
        raw_rules = {}
        if BEARER_RULES_DIR.is_dir():
            rule_paths = chain(
                BEARER_RULES_DIR.rglob("*.yml"), BEARER_RULES_DIR.rglob("*.yaml")
            )
            for rule_path in rule_paths:
                try:
                    data = yaml.safe_load(rule_path.open("r"))
                    rule_id = data["metadata"]["id"]
                    raw_rules[rule_id] = data

                    for aux in data.get("auxiliary", []):
                        raw_rules[aux["id"]] = data
                except (TypeError, KeyError, yaml.composer.ComposerError):  # ty:ignore[possibly-missing-attribute]
                    pass
        return raw_rules

    def get_cwe(self, result: Result, rule_id: str) -> CWE:
        """Get the CWE for a given rule ID."""
        raw_rule = self.raw_rules[rule_id]
        if cwe_ids := raw_rule["metadata"].get("cwe_id"):
            cwe_id = int(cwe_ids[0])
            return CWEs.from_id(cwe_id)
        return CWEs.NOCWE
