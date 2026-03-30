"""Provides classes for parsing Semgrep Community Edition analysis results.

This module defines `SemgrepCEFinding` and `SemgrepCEAnalysisResult` to process
the JSON output from a Semgrep scan, converting it into the standardized
format used by CodeSecTools.
"""

import os
import re
from itertools import chain
from typing import Any

import yaml

from codesectools.sasts.core.parser.format.SARIF import Result
from codesectools.sasts.core.parser.format.SARIF.parser import SARIFAnalysisResult
from codesectools.shared.cwe import CWE, CWEs
from codesectools.utils import USER_CACHE_DIR

SEMGREP_RULES_DIR = USER_CACHE_DIR / "semgrep-rules"


class SemgrepCEAnalysisResult(SARIFAnalysisResult):
    """Represent the complete result of a SemgrepCE analysis from a SARIF file."""

    sast_name = "SemgrepCE"
    rule_categories = [
        "best-practice",
        "correctness",
        "maintainability",
        "performance",
        "portability",
        "security",
    ]

    # Rule id is using full path:
    # home.michel..codesectools.cache.semgrep-rules.java.android.best-practice.manifest-usesCleartextTraffic-true
    # Removing the path to rules to keep only the real rule id:
    # java.android.best-practice.manifest-usesCleartextTraffic-true
    def patch_dict(self, sarif_dict: dict) -> dict:
        """Patch the SARIF dictionary to shorten rule IDs."""
        rule_path_pattern = str(SEMGREP_RULES_DIR).replace(os.sep, ".")[1:] + "."

        def recursive_patch(data: Any) -> None:  # noqa: ANN401
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, str) and rule_path_pattern in value:
                        data[key] = value.replace(rule_path_pattern, "")
                    else:
                        recursive_patch(value)
            elif isinstance(data, list):
                for item in data:
                    recursive_patch(item)

        recursive_patch(sarif_dict)
        self.save_patched_dict(sarif_dict)
        return sarif_dict

    @staticmethod
    # @Cache(SEMGREP_RULES_DIR / ".cstools_cache").memoize(expire=None)
    def get_raw_rules() -> dict:
        """Load and return all Semgrep rules from the cached YAML files."""
        raw_rules = {}
        if SEMGREP_RULES_DIR.is_dir():
            rule_paths = chain(
                SEMGREP_RULES_DIR.rglob("*.yml"), SEMGREP_RULES_DIR.rglob("*.yaml")
            )
            for rule_path in rule_paths:
                try:
                    data = yaml.safe_load(rule_path.open("r"))
                    for rule in data.get("rules"):
                        rule_id = rule["id"]
                        raw_rules[rule_id] = rule
                except (TypeError, KeyError, yaml.composer.ComposerError):  # ty:ignore[possibly-missing-submodule]
                    pass
        return raw_rules

    def get_cwe(self, result: Result, rule_id: str) -> CWE:
        """Get the CWE for a given rule ID."""
        if rule_properties := self.get_rule_properties(rule_id):
            if tags := rule_properties.tags:
                for tag in tags:
                    if m := re.search(r"cwe-(\d+)", tag.lower()):
                        cwe_id = int(m.group(1))
                        return CWEs.from_id(cwe_id)
        return CWEs.NOCWE
