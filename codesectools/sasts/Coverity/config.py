"""Loads and provides configuration for the Coverity integration.

This module reads `issueTypes.json` and `config.json` from the user's
Coverity configuration directory. It creates mappings and settings
used by the Coverity SAST integration.

Attributes:
    USER_COVERITY_DIR (Path): The path to the user's Coverity config directory.
    TYPE_TO_CWE (dict): A mapping from Coverity issue types to CWE IDs.
    LANGUAGES (dict): Configuration for supported languages.
    COLOR_MAPPING (dict): A mapping of result categories to colors for plotting.

"""

import json

from codesectools.utils import USER_CONFIG_DIR, MissingFile

USER_COVERITY_DIR = USER_CONFIG_DIR / "Coverity"

types_file = USER_COVERITY_DIR / "issueTypes.json"

if types_file.is_file():
    TYPES = json.load(types_file.open())["issue_type"]

    TYPE_TO_CWE = {}
    for type in TYPES:
        TYPE_TO_CWE[type["type"]] = type["cim_checker_properties"]["cweCategory"]
else:
    raise MissingFile([types_file.name])

config_file = USER_COVERITY_DIR / "config.json"

if config_file.is_file():
    config = json.load(config_file.open())
    LANGUAGES = config["languages"]
    COLOR_MAPPING = config["color_mapping"]
else:
    raise MissingFile([config_file.name])
