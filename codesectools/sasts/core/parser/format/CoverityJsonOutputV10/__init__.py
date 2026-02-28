"""Coverity JSON Output V10 model."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, Field


class Properties(BaseModel):
    """Represent additional properties in a Coverity issue."""

    fb_priority: Annotated[str | None, Field(alias="fb.priority")] = None
    extra_properties: dict[str, Any] | None = None


class Triage(BaseModel):
    """Represent triage information for a Coverity issue."""

    classification: str | None = None
    action: str | None = None
    fix_target: Annotated[str | None, Field(alias="fixTarget")] = None
    severity: str | None = None
    legacy: str | None = None
    owner: str | None = None
    external_reference: Annotated[str | None, Field(alias="externalReference")] = None


class StateOnServer(BaseModel):
    """Represent the state of a Coverity issue on the server."""

    cid: int
    present_in_reference_snapshot: Annotated[
        bool, Field(alias="presentInReferenceSnapshot")
    ]
    first_detected_date_time: Annotated[str, Field(alias="firstDetectedDateTime")]
    stream: str
    components: list[str]
    triage: Triage | None = None


class Event(BaseModel):
    """Represent an event in a Coverity issue's trace."""

    cov_l_str_event_description: Annotated[
        str | None, Field(alias="covLStrEventDescription")
    ] = None
    event_description: Annotated[str, Field(alias="eventDescription")]
    event_number: Annotated[int, Field(alias="eventNumber")]
    event_tree_position: Annotated[str, Field(alias="eventTreePosition")]
    event_set: Annotated[int, Field(alias="eventSet")]
    event_tag: Annotated[str, Field(alias="eventTag")]
    file_pathname: Annotated[str, Field(alias="filePathname")]
    stripped_file_pathname: Annotated[str, Field(alias="strippedFilePathname")]
    line_number: Annotated[int, Field(alias="lineNumber")]
    column_number: Annotated[int | None, Field(alias="columnNumber")] = None
    main: bool
    more_information_id: Annotated[
        str | int | None, Field(alias="moreInformationId")
    ] = None
    remediation: bool = False
    events: list[Event] | None = None


class CheckerProperties(BaseModel):
    """Represent the properties of a Coverity checker."""

    category: str
    category_description: Annotated[str, Field(alias="categoryDescription")]
    cwe_category: Annotated[str | int | None, Field(alias="cweCategory")] = None
    weakness_id_category: Annotated[str | None, Field(alias="weaknessIdCategory")] = (
        None
    )
    issue_kinds: Annotated[list[str], Field(alias="issueKinds")]
    event_set_captions: Annotated[list[str], Field(alias="eventSetCaptions")]
    impact: str
    impact_description: Annotated[str, Field(alias="impactDescription")]
    subcategory_local_effect: Annotated[
        str | None, Field(alias="subcategoryLocalEffect")
    ] = None
    subcategory_short_description: Annotated[
        str, Field(alias="subcategoryShortDescription")
    ]
    subcategory_long_description: Annotated[
        str, Field(alias="subcategoryLongDescription")
    ]
    subtype: str | None = None
    security_kind: Annotated[bool | None, Field(alias="securityKind")] = None
    quality_kind: Annotated[bool | None, Field(alias="qualityKind")] = None
    test_kind: Annotated[bool | None, Field(alias="testKind")] = None
    origin: str | None = None


class DesktopAnalysisSettings(BaseModel):
    """Represent the settings used for a Coverity desktop analysis."""

    analysis_date: Annotated[str, Field(alias="analysisDate")]
    cmd_line_args: Annotated[list[str], Field(alias="cmdLineArgs")]
    effective_strip_paths: Annotated[list[str], Field(alias="effectiveStripPaths")]
    analysis_scope_pathnames: Annotated[
        list[str], Field(alias="analysisScopePathnames")
    ]
    stripped_analysis_scope_pathnames: Annotated[
        list[str], Field(alias="strippedAnalysisScopePathnames")
    ]
    intermediate_dir: Annotated[str | None, Field(alias="intermediateDir")] = None
    reference_snapshot_details: Annotated[
        dict[str, Any] | None, Field(alias="referenceSnapshotDetails")
    ] = None
    portable_analysis_settings: Annotated[
        dict[str, Any] | None, Field(alias="portableAnalysisSettings")
    ] = None


class Error(BaseModel):
    """Represent an error or warning encountered during Coverity analysis."""

    domain: str | None = None
    code: str | None = None
    message: str | None = None
    file: str | None = None
    line: int | None = None


class Issue(BaseModel):
    """Represent a single issue found by Coverity."""

    merge_key: Annotated[str, Field(alias="mergeKey")]
    occurrence_count_for_mk: Annotated[int, Field(alias="occurrenceCountForMK")]
    occurrence_number_in_mk: Annotated[int, Field(alias="occurrenceNumberInMK")]
    reference_occurrence_count_for_mk: Annotated[
        int | None, Field(alias="referenceOccurrenceCountForMK")
    ] = None
    checker_name: Annotated[str, Field(alias="checkerName")]
    subcategory: str
    type: str
    code_language: Annotated[str, Field(alias="code-language")]
    extra: str | None = None
    domain: str
    language: str | None = None
    main_event_file_pathname: Annotated[str, Field(alias="mainEventFilePathname")]
    stripped_main_event_file_pathname: Annotated[
        str, Field(alias="strippedMainEventFilePathname")
    ]
    main_event_line_number: Annotated[int, Field(alias="mainEventLineNumber")]
    main_event_column_number: Annotated[
        int | None, Field(alias="mainEventColumnNumber")
    ] = None
    properties: Properties | None = None
    function_display_name: Annotated[str | None, Field(alias="functionDisplayName")]
    function_mangled_name: Annotated[str | None, Field(alias="functionMangledName")]
    function_html_display_name: Annotated[
        str | None, Field(alias="functionHtmlDisplayName")
    ]
    function_simple_name: Annotated[str | None, Field(alias="functionSimpleName")]
    function_search_name: Annotated[str | None, Field(alias="functionSearchName")]
    local_status: Annotated[str | None, Field(alias="localStatus")] = None
    ordered: bool
    events: list[Event]
    state_on_server: Annotated[StateOnServer | None, Field(alias="stateOnServer")] = (
        None
    )
    local_triage: Annotated[Triage | None, Field(alias="localTriage")] = None
    checker_properties: Annotated[CheckerProperties, Field(alias="checkerProperties")]
    subtype: str | None = None


class CoverityJsonOutputV10(BaseModel):
    """Represent the root structure of a Coverity JSON V10 output file."""

    type: str
    format_version: Annotated[int, Field(alias="formatVersion")]
    suppressed_issue_count: Annotated[int, Field(alias="suppressedIssueCount")]
    issues: list[Issue]
    desktop_analysis_settings: Annotated[
        DesktopAnalysisSettings | None, Field(alias="desktopAnalysisSettings")
    ] = None
    error: Error | None = None
    warnings: list[Error] = []
