"""Static Analysis Results Interchange Format (SARIF) Version 2.1.0 data model."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AnyUrl, AwareDatetime, BaseModel, ConfigDict, Field, RootModel


class PropertyBag(BaseModel):
    """Key/value pairs that provide additional information about the object."""

    model_config = ConfigDict(
        extra="allow",
    )
    tags: Annotated[
        list[str] | None,
        Field(
            description="A set of distinct strings that provide additional information.",
            min_length=0,
        ),
    ] = []


DeprecatedGuid = RootModel[str]


class ReportingConfiguration(BaseModel):
    """Information about a rule or notification that can be configured at runtime."""

    model_config = ConfigDict(
        extra="forbid",
    )
    enabled: Annotated[
        bool | None,
        Field(
            description="Specifies whether the report may be produced during the scan."
        ),
    ] = True
    level: Annotated[
        Literal["none", "note", "warning", "error"] | None,
        Field(description="Specifies the failure level for the report."),
    ] = "warning"
    rank: Annotated[
        float | None,
        Field(
            description="Specifies the relative priority of the report. Used for analysis output only.",
            ge=-1.0,
            le=100.0,
        ),
    ] = -1.0
    parameters: Annotated[
        PropertyBag | None,
        Field(description="Contains configuration information specific to a report."),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the reporting configuration."
        ),
    ] = None


class ToolComponentReference(BaseModel):
    """Identifies a particular toolComponent object, either the driver or an extension."""

    model_config = ConfigDict(
        extra="forbid",
    )
    name: Annotated[
        str | None,
        Field(description="The 'name' property of the referenced toolComponent."),
    ] = None
    index: Annotated[
        int | None,
        Field(
            description="An index into the referenced toolComponent in tool.extensions.",
            ge=-1,
        ),
    ] = -1
    guid: Annotated[
        str | None,
        Field(
            description="The 'guid' property of the referenced toolComponent.",
            pattern="^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the toolComponentReference."
        ),
    ] = None


class Address(BaseModel):
    """A physical or virtual address, or a range of addresses, in an 'addressable region' (memory or a binary file)."""

    model_config = ConfigDict(
        extra="forbid",
    )
    absolute_address: Annotated[
        int | None,
        Field(
            alias="absoluteAddress",
            description="The address expressed as a byte offset from the start of the addressable region.",
            ge=-1,
        ),
    ] = -1
    relative_address: Annotated[
        int | None,
        Field(
            alias="relativeAddress",
            description="The address expressed as a byte offset from the absolute address of the top-most parent object.",
        ),
    ] = None
    length: Annotated[
        int | None, Field(description="The number of bytes in this range of addresses.")
    ] = None
    kind: Annotated[
        str | None,
        Field(
            description="An open-ended string that identifies the address kind. 'data', 'function', 'header','instruction', 'module', 'page', 'section', 'segment', 'stack', 'stackFrame', 'table' are well-known values."
        ),
    ] = None
    name: Annotated[
        str | None,
        Field(description="A name that is associated with the address, e.g., '.text'."),
    ] = None
    fully_qualified_name: Annotated[
        str | None,
        Field(
            alias="fullyQualifiedName",
            description="A human-readable fully qualified name that is associated with the address.",
        ),
    ] = None
    offset_from_parent: Annotated[
        int | None,
        Field(
            alias="offsetFromParent",
            description="The byte offset of this address from the absolute or relative address of the parent object.",
        ),
    ] = None
    index: Annotated[
        int | None,
        Field(
            description="The index within run.addresses of the cached object for this address.",
            ge=-1,
        ),
    ] = -1
    parent_index: Annotated[
        int | None,
        Field(
            alias="parentIndex",
            description="The index within run.addresses of the parent object.",
            ge=-1,
        ),
    ] = -1
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the address."
        ),
    ] = None


class LogicalLocation(BaseModel):
    """A logical location of a construct that produced a result."""

    model_config = ConfigDict(
        extra="forbid",
    )
    name: Annotated[
        str | None,
        Field(
            description="Identifies the construct in which the result occurred. For example, this property might contain the name of a class or a method."
        ),
    ] = None
    index: Annotated[
        int | None,
        Field(description="The index within the logical locations array.", ge=-1),
    ] = -1
    fully_qualified_name: Annotated[
        str | None,
        Field(
            alias="fullyQualifiedName",
            description="The human-readable fully qualified name of the logical location.",
        ),
    ] = None
    decorated_name: Annotated[
        str | None,
        Field(
            alias="decoratedName",
            description="The machine-readable name for the logical location, such as a mangled function name provided by a C++ compiler that encodes calling convention, return type and other details along with the function name.",
        ),
    ] = None
    parent_index: Annotated[
        int | None,
        Field(
            alias="parentIndex",
            description="Identifies the index of the immediate parent of the construct in which the result was detected. For example, this property might point to a logical location that represents the namespace that holds a type.",
            ge=-1,
        ),
    ] = -1
    kind: Annotated[
        str | None,
        Field(
            description="The type of construct this logical location component refers to. Should be one of 'function', 'member', 'module', 'namespace', 'parameter', 'resource', 'returnType', 'type', 'variable', 'object', 'array', 'property', 'value', 'element', 'text', 'attribute', 'comment', 'declaration', 'dtd' or 'processingInstruction', if any of those accurately describe the construct."
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the logical location."
        ),
    ] = None


class Message1(BaseModel):
    """Encapsulates a message intended to be read by the end user."""

    model_config = ConfigDict(
        extra="forbid",
    )
    text: Annotated[str, Field(description="A plain text message string.")]
    markdown: Annotated[str | None, Field(description="A Markdown message string.")] = (
        None
    )
    id: Annotated[str | None, Field(description="The identifier for this message.")] = (
        None
    )
    arguments: Annotated[
        list[str] | None,
        Field(
            description="An array of strings to substitute into the message string.",
            min_length=0,
        ),
    ] = []
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the message."
        ),
    ] = None


class Message2(BaseModel):
    """Encapsulates a message intended to be read by the end user."""

    model_config = ConfigDict(
        extra="forbid",
    )
    text: Annotated[str | None, Field(description="A plain text message string.")] = (
        None
    )
    markdown: Annotated[str | None, Field(description="A Markdown message string.")] = (
        None
    )
    id: Annotated[str, Field(description="The identifier for this message.")]
    arguments: Annotated[
        list[str] | None,
        Field(
            description="An array of strings to substitute into the message string.",
            min_length=0,
        ),
    ] = []
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the message."
        ),
    ] = None


Message = RootModel[Message1 | Message2]


class MultiformatMessageString(BaseModel):
    """A message string or message format string rendered in multiple formats."""

    model_config = ConfigDict(
        extra="forbid",
    )
    text: Annotated[
        str, Field(description="A plain text message string or format string.")
    ]
    markdown: Annotated[
        str | None, Field(description="A Markdown message string or format string.")
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the message."
        ),
    ] = None


class Rectangle(BaseModel):
    """An area within an image."""

    model_config = ConfigDict(
        extra="forbid",
    )
    top: Annotated[
        float | None,
        Field(
            description="The Y coordinate of the top edge of the rectangle, measured in the image's natural units."
        ),
    ] = None
    left: Annotated[
        float | None,
        Field(
            description="The X coordinate of the left edge of the rectangle, measured in the image's natural units."
        ),
    ] = None
    bottom: Annotated[
        float | None,
        Field(
            description="The Y coordinate of the bottom edge of the rectangle, measured in the image's natural units."
        ),
    ] = None
    right: Annotated[
        float | None,
        Field(
            description="The X coordinate of the right edge of the rectangle, measured in the image's natural units."
        ),
    ] = None
    message: Annotated[
        Message | None, Field(description="A message relevant to the rectangle.")
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the rectangle."
        ),
    ] = None


class ReportingDescriptorReference1(BaseModel):
    """Information about how to locate a relevant reporting descriptor."""

    model_config = ConfigDict(
        extra="forbid",
    )
    id: Annotated[str | None, Field(description="The id of the descriptor.")] = None
    index: Annotated[
        int,
        Field(
            description="The index into an array of descriptors in toolComponent.ruleDescriptors, toolComponent.notificationDescriptors, or toolComponent.taxonomyDescriptors, depending on context.",
            ge=-1,
        ),
    ]
    guid: Annotated[
        str | None,
        Field(
            description="A guid that uniquely identifies the descriptor.",
            pattern="^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        ),
    ] = None
    tool_component: Annotated[
        ToolComponentReference | None,
        Field(
            alias="toolComponent",
            description="A reference used to locate the toolComponent associated with the descriptor.",
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the reporting descriptor reference."
        ),
    ] = None


class ReportingDescriptorReference2(BaseModel):
    """Information about how to locate a relevant reporting descriptor."""

    model_config = ConfigDict(
        extra="forbid",
    )
    id: Annotated[str | None, Field(description="The id of the descriptor.")] = None
    index: Annotated[
        int | None,
        Field(
            description="The index into an array of descriptors in toolComponent.ruleDescriptors, toolComponent.notificationDescriptors, or toolComponent.taxonomyDescriptors, depending on context.",
            ge=-1,
        ),
    ] = -1
    guid: Annotated[
        str,
        Field(
            description="A guid that uniquely identifies the descriptor.",
            pattern="^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        ),
    ]
    tool_component: Annotated[
        ToolComponentReference | None,
        Field(
            alias="toolComponent",
            description="A reference used to locate the toolComponent associated with the descriptor.",
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the reporting descriptor reference."
        ),
    ] = None


class ReportingDescriptorReference3(BaseModel):
    """Information about how to locate a relevant reporting descriptor."""

    model_config = ConfigDict(
        extra="forbid",
    )
    id: Annotated[str, Field(description="The id of the descriptor.")]
    index: Annotated[
        int | None,
        Field(
            description="The index into an array of descriptors in toolComponent.ruleDescriptors, toolComponent.notificationDescriptors, or toolComponent.taxonomyDescriptors, depending on context.",
            ge=-1,
        ),
    ] = -1
    guid: Annotated[
        str | None,
        Field(
            description="A guid that uniquely identifies the descriptor.",
            pattern="^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        ),
    ] = None
    tool_component: Annotated[
        ToolComponentReference | None,
        Field(
            alias="toolComponent",
            description="A reference used to locate the toolComponent associated with the descriptor.",
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the reporting descriptor reference."
        ),
    ] = None


ReportingDescriptorReference = RootModel[
    ReportingDescriptorReference1
    | ReportingDescriptorReference2
    | ReportingDescriptorReference3
]


class ReportingDescriptorRelationship(BaseModel):
    """Information about the relation of one reporting descriptor to another."""

    model_config = ConfigDict(
        extra="forbid",
    )
    target: Annotated[
        ReportingDescriptorReference,
        Field(description="A reference to the related reporting descriptor."),
    ]
    kinds: Annotated[
        list[str] | None,
        Field(
            description="A set of distinct strings that categorize the relationship. Well-known kinds include 'canPrecede', 'canFollow', 'willPrecede', 'willFollow', 'superset', 'subset', 'equal', 'disjoint', 'relevant', and 'incomparable'."
        ),
    ] = ["relevant"]
    description: Annotated[
        Message | None,
        Field(description="A description of the reporting descriptor relationship."),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the reporting descriptor reference."
        ),
    ] = None


class RunAutomationDetails(BaseModel):
    """Information that describes a run's identity and role within an engineering system process."""

    model_config = ConfigDict(
        extra="forbid",
    )
    description: Annotated[
        Message | None,
        Field(
            description="A description of the identity and role played within the engineering system by this object's containing run object."
        ),
    ] = None
    id: Annotated[
        str | None,
        Field(
            description="A hierarchical string that uniquely identifies this object's containing run object."
        ),
    ] = None
    guid: Annotated[
        str | None,
        Field(
            description="A stable, unique identifer for this object's containing run object in the form of a GUID.",
            pattern="^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        ),
    ] = None
    correlation_guid: Annotated[
        str | None,
        Field(
            alias="correlationGuid",
            description="A stable, unique identifier for the equivalence class of runs to which this object's containing run object belongs in the form of a GUID.",
            pattern="^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the run automation details."
        ),
    ] = None


class TranslationMetadata(BaseModel):
    """Provides additional metadata related to translation."""

    model_config = ConfigDict(
        extra="forbid",
    )
    name: Annotated[
        str, Field(description="The name associated with the translation metadata.")
    ]
    full_name: Annotated[
        str | None,
        Field(
            alias="fullName",
            description="The full name associated with the translation metadata.",
        ),
    ] = None
    short_description: Annotated[
        MultiformatMessageString | None,
        Field(
            alias="shortDescription",
            description="A brief description of the translation metadata.",
        ),
    ] = None
    full_description: Annotated[
        MultiformatMessageString | None,
        Field(
            alias="fullDescription",
            description="A comprehensive description of the translation metadata.",
        ),
    ] = None
    download_uri: Annotated[
        AnyUrl | None,
        Field(
            alias="downloadUri",
            description="The absolute URI from which the translation metadata can be downloaded.",
        ),
    ] = None
    information_uri: Annotated[
        AnyUrl | None,
        Field(
            alias="informationUri",
            description="The absolute URI from which information related to the translation metadata can be downloaded.",
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the translation metadata."
        ),
    ] = None


class ArtifactContent(BaseModel):
    """Represents the contents of an artifact."""

    model_config = ConfigDict(
        extra="forbid",
    )
    text: Annotated[
        str | None, Field(description="UTF-8-encoded content from a text artifact.")
    ] = None
    binary: Annotated[
        str | None,
        Field(
            description="MIME Base64-encoded content from a binary artifact, or from a text artifact in its original encoding."
        ),
    ] = None
    rendered: Annotated[
        MultiformatMessageString | None,
        Field(
            description="An alternate rendered representation of the artifact (e.g., a decompiled representation of a binary region)."
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the artifact content."
        ),
    ] = None


class ArtifactLocation(BaseModel):
    """Specifies the location of an artifact."""

    model_config = ConfigDict(
        extra="forbid",
    )
    uri: Annotated[
        str | None,
        Field(description="A string containing a valid relative or absolute URI."),
    ] = None
    uri_base_id: Annotated[
        str | None,
        Field(
            alias="uriBaseId",
            description='A string which indirectly specifies the absolute URI with respect to which a relative URI in the "uri" property is interpreted.',
        ),
    ] = None
    index: Annotated[
        int | None,
        Field(
            description="The index within the run artifacts array of the artifact object associated with the artifact location.",
            ge=-1,
        ),
    ] = -1
    description: Annotated[
        Message | None,
        Field(description="A short description of the artifact location."),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the artifact location."
        ),
    ] = None


class ConfigurationOverride(BaseModel):
    """Information about how a specific rule or notification was reconfigured at runtime."""

    model_config = ConfigDict(
        extra="forbid",
    )
    configuration: Annotated[
        ReportingConfiguration,
        Field(
            description="Specifies how the rule or notification was configured during the scan."
        ),
    ]
    descriptor: Annotated[
        ReportingDescriptorReference,
        Field(
            description="A reference used to locate the descriptor whose configuration was overridden."
        ),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the configuration override."
        ),
    ] = None


class Edge(BaseModel):
    """Represents a directed edge in a graph."""

    model_config = ConfigDict(
        extra="forbid",
    )
    id: Annotated[
        str,
        Field(
            description="A string that uniquely identifies the edge within its graph."
        ),
    ]
    label: Annotated[
        Message | None, Field(description="A short description of the edge.")
    ] = None
    source_node_id: Annotated[
        str,
        Field(
            alias="sourceNodeId",
            description="Identifies the source node (the node at which the edge starts).",
        ),
    ]
    target_node_id: Annotated[
        str,
        Field(
            alias="targetNodeId",
            description="Identifies the target node (the node at which the edge ends).",
        ),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the edge."
        ),
    ] = None


class EdgeTraversal(BaseModel):
    """Represents the traversal of a single edge during a graph traversal."""

    model_config = ConfigDict(
        extra="forbid",
    )
    edge_id: Annotated[
        str, Field(alias="edgeId", description="Identifies the edge being traversed.")
    ]
    message: Annotated[
        Message | None,
        Field(description="A message to display to the user as the edge is traversed."),
    ] = None
    final_state: Annotated[
        dict[str, MultiformatMessageString] | None,
        Field(
            alias="finalState",
            description="The values of relevant expressions after the edge has been traversed.",
        ),
    ] = None
    step_over_edge_count: Annotated[
        int | None,
        Field(
            alias="stepOverEdgeCount",
            description="The number of edge traversals necessary to return from a nested graph.",
            ge=0,
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the edge traversal."
        ),
    ] = None


class ExternalPropertyFileReference1(BaseModel):
    """Contains information that enables a SARIF consumer to locate the external property file that contains the value of an externalized property associated with the run."""

    model_config = ConfigDict(
        extra="forbid",
    )
    location: Annotated[
        ArtifactLocation,
        Field(description="The location of the external property file."),
    ]
    guid: Annotated[
        str | None,
        Field(
            description="A stable, unique identifer for the external property file in the form of a GUID.",
            pattern="^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        ),
    ] = None
    item_count: Annotated[
        int | None,
        Field(
            alias="itemCount",
            description="A non-negative integer specifying the number of items contained in the external property file.",
            ge=-1,
        ),
    ] = -1
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the external property file."
        ),
    ] = None


class ExternalPropertyFileReference2(BaseModel):
    """Contains information that enables a SARIF consumer to locate the external property file that contains the value of an externalized property associated with the run."""

    model_config = ConfigDict(
        extra="forbid",
    )
    location: Annotated[
        ArtifactLocation | None,
        Field(description="The location of the external property file."),
    ] = None
    guid: Annotated[
        str,
        Field(
            description="A stable, unique identifer for the external property file in the form of a GUID.",
            pattern="^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        ),
    ]
    item_count: Annotated[
        int | None,
        Field(
            alias="itemCount",
            description="A non-negative integer specifying the number of items contained in the external property file.",
            ge=-1,
        ),
    ] = -1
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the external property file."
        ),
    ] = None


ExternalPropertyFileReference = RootModel[
    ExternalPropertyFileReference1 | ExternalPropertyFileReference2
]


class ExternalPropertyFileReferences(BaseModel):
    """References to external property files that should be inlined with the content of a root log file."""

    model_config = ConfigDict(
        extra="forbid",
    )
    conversion: Annotated[
        ExternalPropertyFileReference | None,
        Field(
            description="An external property file containing a run.conversion object to be merged with the root log file."
        ),
    ] = None
    graphs: Annotated[
        list[ExternalPropertyFileReference] | None,
        Field(
            default_factory=list,
            description="An array of external property files containing a run.graphs object to be merged with the root log file.",
            min_length=0,
        ),
    ]
    externalized_properties: Annotated[
        ExternalPropertyFileReference | None,
        Field(
            alias="externalizedProperties",
            description="An external property file containing a run.properties object to be merged with the root log file.",
        ),
    ] = None
    artifacts: Annotated[
        list[ExternalPropertyFileReference] | None,
        Field(
            default_factory=list,
            description="An array of external property files containing run.artifacts arrays to be merged with the root log file.",
            min_length=0,
        ),
    ]
    invocations: Annotated[
        list[ExternalPropertyFileReference] | None,
        Field(
            default_factory=list,
            description="An array of external property files containing run.invocations arrays to be merged with the root log file.",
            min_length=0,
        ),
    ]
    logical_locations: Annotated[
        list[ExternalPropertyFileReference] | None,
        Field(
            default_factory=list,
            alias="logicalLocations",
            description="An array of external property files containing run.logicalLocations arrays to be merged with the root log file.",
            min_length=0,
        ),
    ]
    thread_flow_locations: Annotated[
        list[ExternalPropertyFileReference] | None,
        Field(
            default_factory=list,
            alias="threadFlowLocations",
            description="An array of external property files containing run.threadFlowLocations arrays to be merged with the root log file.",
            min_length=0,
        ),
    ]
    results: Annotated[
        list[ExternalPropertyFileReference] | None,
        Field(
            default_factory=list,
            description="An array of external property files containing run.results arrays to be merged with the root log file.",
            min_length=0,
        ),
    ]
    taxonomies: Annotated[
        list[ExternalPropertyFileReference] | None,
        Field(
            default_factory=list,
            description="An array of external property files containing run.taxonomies arrays to be merged with the root log file.",
            min_length=0,
        ),
    ]
    addresses: Annotated[
        list[ExternalPropertyFileReference] | None,
        Field(
            default_factory=list,
            description="An array of external property files containing run.addresses arrays to be merged with the root log file.",
            min_length=0,
        ),
    ]
    driver: Annotated[
        ExternalPropertyFileReference | None,
        Field(
            description="An external property file containing a run.driver object to be merged with the root log file."
        ),
    ] = None
    extensions: Annotated[
        list[ExternalPropertyFileReference] | None,
        Field(
            default_factory=list,
            description="An array of external property files containing run.extensions arrays to be merged with the root log file.",
            min_length=0,
        ),
    ]
    policies: Annotated[
        list[ExternalPropertyFileReference] | None,
        Field(
            default_factory=list,
            description="An array of external property files containing run.policies arrays to be merged with the root log file.",
            min_length=0,
        ),
    ]
    translations: Annotated[
        list[ExternalPropertyFileReference] | None,
        Field(
            default_factory=list,
            description="An array of external property files containing run.translations arrays to be merged with the root log file.",
            min_length=0,
        ),
    ]
    web_requests: Annotated[
        list[ExternalPropertyFileReference] | None,
        Field(
            default_factory=list,
            alias="webRequests",
            description="An array of external property files containing run.requests arrays to be merged with the root log file.",
            min_length=0,
        ),
    ]
    web_responses: Annotated[
        list[ExternalPropertyFileReference] | None,
        Field(
            default_factory=list,
            alias="webResponses",
            description="An array of external property files containing run.responses arrays to be merged with the root log file.",
            min_length=0,
        ),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the external property files."
        ),
    ] = None


class GraphTraversal1(BaseModel):
    """Represents a path through a graph."""

    model_config = ConfigDict(
        extra="forbid",
    )
    run_graph_index: Annotated[
        int,
        Field(
            alias="runGraphIndex",
            description="The index within the run.graphs to be associated with the result.",
            ge=-1,
        ),
    ]
    result_graph_index: Annotated[
        int | None,
        Field(
            alias="resultGraphIndex",
            description="The index within the result.graphs to be associated with the result.",
            ge=-1,
        ),
    ] = -1
    description: Annotated[
        Message | None, Field(description="A description of this graph traversal.")
    ] = None
    initial_state: Annotated[
        dict[str, MultiformatMessageString] | None,
        Field(
            alias="initialState",
            description="Values of relevant expressions at the start of the graph traversal that may change during graph traversal.",
        ),
    ] = None
    immutable_state: Annotated[
        dict[str, MultiformatMessageString] | None,
        Field(
            alias="immutableState",
            description="Values of relevant expressions at the start of the graph traversal that remain constant for the graph traversal.",
        ),
    ] = None
    edge_traversals: Annotated[
        list[EdgeTraversal] | None,
        Field(
            default_factory=list,
            alias="edgeTraversals",
            description="The sequences of edges traversed by this graph traversal.",
            min_length=0,
        ),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the graph traversal."
        ),
    ] = None


class GraphTraversal2(BaseModel):
    """Represents a path through a graph."""

    model_config = ConfigDict(
        extra="forbid",
    )
    run_graph_index: Annotated[
        int | None,
        Field(
            alias="runGraphIndex",
            description="The index within the run.graphs to be associated with the result.",
            ge=-1,
        ),
    ] = -1
    result_graph_index: Annotated[
        int,
        Field(
            alias="resultGraphIndex",
            description="The index within the result.graphs to be associated with the result.",
            ge=-1,
        ),
    ]
    description: Annotated[
        Message | None, Field(description="A description of this graph traversal.")
    ] = None
    initial_state: Annotated[
        dict[str, MultiformatMessageString] | None,
        Field(
            alias="initialState",
            description="Values of relevant expressions at the start of the graph traversal that may change during graph traversal.",
        ),
    ] = None
    immutable_state: Annotated[
        dict[str, MultiformatMessageString] | None,
        Field(
            alias="immutableState",
            description="Values of relevant expressions at the start of the graph traversal that remain constant for the graph traversal.",
        ),
    ] = None
    edge_traversals: Annotated[
        list[EdgeTraversal] | None,
        Field(
            default_factory=list,
            alias="edgeTraversals",
            description="The sequences of edges traversed by this graph traversal.",
            min_length=0,
        ),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the graph traversal."
        ),
    ] = None


GraphTraversal = RootModel[GraphTraversal1 | GraphTraversal2]


class LocationRelationship(BaseModel):
    """Information about the relation of one location to another."""

    model_config = ConfigDict(
        extra="forbid",
    )
    target: Annotated[
        int, Field(description="A reference to the related location.", ge=0)
    ]
    kinds: Annotated[
        list[str] | None,
        Field(
            description="A set of distinct strings that categorize the relationship. Well-known kinds include 'includes', 'isIncludedBy' and 'relevant'."
        ),
    ] = ["relevant"]
    description: Annotated[
        Message | None, Field(description="A description of the location relationship.")
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the location relationship."
        ),
    ] = None


class Region(BaseModel):
    """A region within an artifact where a result was detected."""

    model_config = ConfigDict(
        extra="forbid",
    )
    start_line: Annotated[
        int | None,
        Field(
            alias="startLine",
            description="The line number of the first character in the region.",
            ge=1,
        ),
    ] = None
    start_column: Annotated[
        int | None,
        Field(
            alias="startColumn",
            description="The column number of the first character in the region.",
            ge=1,
        ),
    ] = None
    end_line: Annotated[
        int | None,
        Field(
            alias="endLine",
            description="The line number of the last character in the region.",
            ge=1,
        ),
    ] = None
    end_column: Annotated[
        int | None,
        Field(
            alias="endColumn",
            description="The column number of the character following the end of the region.",
            ge=1,
        ),
    ] = None
    char_offset: Annotated[
        int | None,
        Field(
            alias="charOffset",
            description="The zero-based offset from the beginning of the artifact of the first character in the region.",
            ge=-1,
        ),
    ] = -1
    char_length: Annotated[
        int | None,
        Field(
            alias="charLength",
            description="The length of the region in characters.",
            ge=0,
        ),
    ] = None
    byte_offset: Annotated[
        int | None,
        Field(
            alias="byteOffset",
            description="The zero-based offset from the beginning of the artifact of the first byte in the region.",
            ge=-1,
        ),
    ] = -1
    byte_length: Annotated[
        int | None,
        Field(
            alias="byteLength", description="The length of the region in bytes.", ge=0
        ),
    ] = None
    snippet: Annotated[
        ArtifactContent | None,
        Field(
            description="The portion of the artifact contents within the specified region."
        ),
    ] = None
    message: Annotated[
        Message | None, Field(description="A message relevant to the region.")
    ] = None
    source_language: Annotated[
        str | None,
        Field(
            alias="sourceLanguage",
            description="Specifies the source language, if any, of the portion of the artifact specified by the region object.",
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the region."
        ),
    ] = None


class Replacement(BaseModel):
    """The replacement of a single region of an artifact."""

    model_config = ConfigDict(
        extra="forbid",
    )
    deleted_region: Annotated[
        Region,
        Field(
            alias="deletedRegion", description="The region of the artifact to delete."
        ),
    ]
    inserted_content: Annotated[
        ArtifactContent | None,
        Field(
            alias="insertedContent",
            description="The content to insert at the location specified by the 'deletedRegion' property.",
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the replacement."
        ),
    ] = None


class ReportingDescriptor(BaseModel):
    """Metadata that describes a specific report produced by the tool, as part of the analysis it provides or its runtime reporting."""

    model_config = ConfigDict(
        extra="forbid",
    )
    id: Annotated[str, Field(description="A stable, opaque identifier for the report.")]
    deprecated_ids: Annotated[
        list[str] | None,
        Field(
            alias="deprecatedIds",
            description="An array of stable, opaque identifiers by which this report was known in some previous version of the analysis tool.",
            min_length=0,
        ),
    ] = None
    guid: Annotated[
        str | None,
        Field(
            description="A unique identifer for the reporting descriptor in the form of a GUID.",
            pattern="^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        ),
    ] = None
    deprecated_guids: Annotated[
        list[DeprecatedGuid] | None,
        Field(
            alias="deprecatedGuids",
            description="An array of unique identifies in the form of a GUID by which this report was known in some previous version of the analysis tool.",
            min_length=0,
        ),
    ] = None
    name: Annotated[
        str | None,
        Field(description="A report identifier that is understandable to an end user."),
    ] = None
    deprecated_names: Annotated[
        list[str] | None,
        Field(
            alias="deprecatedNames",
            description="An array of readable identifiers by which this report was known in some previous version of the analysis tool.",
            min_length=0,
        ),
    ] = None
    short_description: Annotated[
        MultiformatMessageString | None,
        Field(
            alias="shortDescription",
            description="A concise description of the report. Should be a single sentence that is understandable when visible space is limited to a single line of text.",
        ),
    ] = None
    full_description: Annotated[
        MultiformatMessageString | None,
        Field(
            alias="fullDescription",
            description="A description of the report. Should, as far as possible, provide details sufficient to enable resolution of any problem indicated by the result.",
        ),
    ] = None
    message_strings: Annotated[
        dict[str, MultiformatMessageString] | None,
        Field(
            alias="messageStrings",
            description="A set of name/value pairs with arbitrary names. Each value is a multiformatMessageString object, which holds message strings in plain text and (optionally) Markdown format. The strings can include placeholders, which can be used to construct a message in combination with an arbitrary number of additional string arguments.",
        ),
    ] = None
    default_configuration: Annotated[
        ReportingConfiguration | None,
        Field(
            alias="defaultConfiguration",
            description="Default reporting configuration information.",
        ),
    ] = None
    help_uri: Annotated[
        AnyUrl | None,
        Field(
            alias="helpUri",
            description="A URI where the primary documentation for the report can be found.",
        ),
    ] = None
    help: Annotated[
        MultiformatMessageString | None,
        Field(
            description="Provides the primary documentation for the report, useful when there is no online documentation."
        ),
    ] = None
    relationships: Annotated[
        list[ReportingDescriptorRelationship] | None,
        Field(
            default_factory=list,
            description="An array of objects that describe relationships between this reporting descriptor and others.",
            min_length=0,
        ),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the report."
        ),
    ] = None


class SpecialLocations(BaseModel):
    """Defines locations of special significance to SARIF consumers."""

    model_config = ConfigDict(
        extra="forbid",
    )
    display_base: Annotated[
        ArtifactLocation | None,
        Field(
            alias="displayBase",
            description="Provides a suggestion to SARIF consumers to display file paths relative to the specified location.",
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the special locations."
        ),
    ] = None


class ToolComponent(BaseModel):
    """A component, such as a plug-in or the driver, of the analysis tool that was run."""

    model_config = ConfigDict(
        extra="forbid",
    )
    guid: Annotated[
        str | None,
        Field(
            description="A unique identifer for the tool component in the form of a GUID.",
            pattern="^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        ),
    ] = None
    name: Annotated[str, Field(description="The name of the tool component.")]
    organization: Annotated[
        str | None,
        Field(
            description="The organization or company that produced the tool component."
        ),
    ] = None
    product: Annotated[
        str | None,
        Field(description="A product suite to which the tool component belongs."),
    ] = None
    product_suite: Annotated[
        str | None,
        Field(
            alias="productSuite",
            description="A localizable string containing the name of the suite of products to which the tool component belongs.",
        ),
    ] = None
    short_description: Annotated[
        MultiformatMessageString | None,
        Field(
            alias="shortDescription",
            description="A brief description of the tool component.",
        ),
    ] = None
    full_description: Annotated[
        MultiformatMessageString | None,
        Field(
            alias="fullDescription",
            description="A comprehensive description of the tool component.",
        ),
    ] = None
    full_name: Annotated[
        str | None,
        Field(
            alias="fullName",
            description="The name of the tool component along with its version and any other useful identifying information, such as its locale.",
        ),
    ] = None
    version: Annotated[
        str | None,
        Field(
            description="The tool component version, in whatever format the component natively provides."
        ),
    ] = None
    semantic_version: Annotated[
        str | None,
        Field(
            alias="semanticVersion",
            description="The tool component version in the format specified by Semantic Versioning 2.0.",
        ),
    ] = None
    dotted_quad_file_version: Annotated[
        str | None,
        Field(
            alias="dottedQuadFileVersion",
            description="The binary version of the tool component's primary executable file expressed as four non-negative integers separated by a period (for operating systems that express file versions in this way).",
            pattern="[0-9]+(\\.[0-9]+){3}",
        ),
    ] = None
    release_date_utc: Annotated[
        str | None,
        Field(
            alias="releaseDateUtc",
            description="A string specifying the UTC date (and optionally, the time) of the component's release.",
        ),
    ] = None
    download_uri: Annotated[
        AnyUrl | None,
        Field(
            alias="downloadUri",
            description="The absolute URI from which the tool component can be downloaded.",
        ),
    ] = None
    information_uri: Annotated[
        AnyUrl | None,
        Field(
            alias="informationUri",
            description="The absolute URI at which information about this version of the tool component can be found.",
        ),
    ] = None
    global_message_strings: Annotated[
        dict[str, MultiformatMessageString] | None,
        Field(
            alias="globalMessageStrings",
            description="A dictionary, each of whose keys is a resource identifier and each of whose values is a multiformatMessageString object, which holds message strings in plain text and (optionally) Markdown format. The strings can include placeholders, which can be used to construct a message in combination with an arbitrary number of additional string arguments.",
        ),
    ] = None
    notifications: Annotated[
        list[ReportingDescriptor] | None,
        Field(
            default_factory=list,
            description="An array of reportingDescriptor objects relevant to the notifications related to the configuration and runtime execution of the tool component.",
            min_length=0,
        ),
    ]
    rules: Annotated[
        list[ReportingDescriptor] | None,
        Field(
            default_factory=list,
            description="An array of reportingDescriptor objects relevant to the analysis performed by the tool component.",
            min_length=0,
        ),
    ]
    taxa: Annotated[
        list[ReportingDescriptor] | None,
        Field(
            default_factory=list,
            description="An array of reportingDescriptor objects relevant to the definitions of both standalone and tool-defined taxonomies.",
            min_length=0,
        ),
    ]
    locations: Annotated[
        list[ArtifactLocation] | None,
        Field(
            default_factory=list,
            description="An array of the artifactLocation objects associated with the tool component.",
            min_length=0,
        ),
    ]
    language: Annotated[
        str | None,
        Field(
            description="The language of the messages emitted into the log file during this run (expressed as an ISO 639-1 two-letter lowercase language code) and an optional region (expressed as an ISO 3166-1 two-letter uppercase subculture code associated with a country or region). The casing is recommended but not required (in order for this data to conform to RFC5646).",
            pattern="^[a-zA-Z]{2}|^[a-zA-Z]{2}-[a-zA-Z]{2}]?$",
        ),
    ] = "en-US"
    contents: Annotated[
        list[Literal["localizedData", "nonLocalizedData"]] | None,
        Field(description="The kinds of data contained in this object."),
    ] = ["localizedData", "nonLocalizedData"]
    is_comprehensive: Annotated[
        bool | None,
        Field(
            alias="isComprehensive",
            description="Specifies whether this object contains a complete definition of the localizable and/or non-localizable data for this component, as opposed to including only data that is relevant to the results persisted to this log file.",
        ),
    ] = False
    localized_data_semantic_version: Annotated[
        str | None,
        Field(
            alias="localizedDataSemanticVersion",
            description="The semantic version of the localized strings defined in this component; maintained by components that provide translations.",
        ),
    ] = None
    minimum_required_localized_data_semantic_version: Annotated[
        str | None,
        Field(
            alias="minimumRequiredLocalizedDataSemanticVersion",
            description="The minimum value of localizedDataSemanticVersion required in translations consumed by this component; used by components that consume translations.",
        ),
    ] = None
    associated_component: Annotated[
        ToolComponentReference | None,
        Field(
            alias="associatedComponent",
            description="The component which is strongly associated with this component. For a translation, this refers to the component which has been translated. For an extension, this is the driver that provides the extension's plugin model.",
        ),
    ] = None
    translation_metadata: Annotated[
        TranslationMetadata | None,
        Field(
            alias="translationMetadata",
            description="Translation metadata, required for a translation, not populated by other component types.",
        ),
    ] = None
    supported_taxonomies: Annotated[
        list[ToolComponentReference] | None,
        Field(
            default_factory=list,
            alias="supportedTaxonomies",
            description="An array of toolComponentReference objects to declare the taxonomies supported by the tool component.",
            min_length=0,
        ),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the tool component."
        ),
    ] = None


class VersionControlDetails(BaseModel):
    """Specifies the information necessary to retrieve a desired revision from a version control system."""

    model_config = ConfigDict(
        extra="forbid",
    )
    repository_uri: Annotated[
        AnyUrl,
        Field(alias="repositoryUri", description="The absolute URI of the repository."),
    ]
    revision_id: Annotated[
        str | None,
        Field(
            alias="revisionId",
            description="A string that uniquely and permanently identifies the revision within the repository.",
        ),
    ] = None
    branch: Annotated[
        str | None, Field(description="The name of a branch containing the revision.")
    ] = None
    revision_tag: Annotated[
        str | None,
        Field(
            alias="revisionTag",
            description="A tag that has been applied to the revision.",
        ),
    ] = None
    as_of_time_utc: Annotated[
        AwareDatetime | None,
        Field(
            alias="asOfTimeUtc",
            description="A Coordinated Universal Time (UTC) date and time that can be used to synchronize an enlistment to the state of the repository at that time.",
        ),
    ] = None
    mapped_to: Annotated[
        ArtifactLocation | None,
        Field(
            alias="mappedTo",
            description="The location in the local file system to which the root of the repository was mapped at the time of the analysis.",
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the version control details."
        ),
    ] = None


class WebRequest(BaseModel):
    """Describes an HTTP request."""

    model_config = ConfigDict(
        extra="forbid",
    )
    index: Annotated[
        int | None,
        Field(
            description="The index within the run.webRequests array of the request object associated with this result.",
            ge=-1,
        ),
    ] = -1
    protocol: Annotated[
        str | None, Field(description="The request protocol. Example: 'http'.")
    ] = None
    version: Annotated[
        str | None, Field(description="The request version. Example: '1.1'.")
    ] = None
    target: Annotated[str | None, Field(description="The target of the request.")] = (
        None
    )
    method: Annotated[
        str | None,
        Field(
            description="The HTTP method. Well-known values are 'GET', 'PUT', 'POST', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'."
        ),
    ] = None
    headers: Annotated[
        dict[str, str] | None, Field(description="The request headers.")
    ] = None
    parameters: Annotated[
        dict[str, str] | None, Field(description="The request parameters.")
    ] = None
    body: Annotated[
        ArtifactContent | None, Field(description="The body of the request.")
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the request."
        ),
    ] = None


class WebResponse(BaseModel):
    """Describes the response to an HTTP request."""

    model_config = ConfigDict(
        extra="forbid",
    )
    index: Annotated[
        int | None,
        Field(
            description="The index within the run.webResponses array of the response object associated with this result.",
            ge=-1,
        ),
    ] = -1
    protocol: Annotated[
        str | None, Field(description="The response protocol. Example: 'http'.")
    ] = None
    version: Annotated[
        str | None, Field(description="The response version. Example: '1.1'.")
    ] = None
    status_code: Annotated[
        int | None,
        Field(
            alias="statusCode", description="The response status code. Example: 451."
        ),
    ] = None
    reason_phrase: Annotated[
        str | None,
        Field(
            alias="reasonPhrase",
            description="The response reason. Example: 'Not found'.",
        ),
    ] = None
    headers: Annotated[
        dict[str, str] | None, Field(description="The response headers.")
    ] = None
    body: Annotated[
        ArtifactContent | None, Field(description="The body of the response.")
    ] = None
    no_response_received: Annotated[
        bool | None,
        Field(
            alias="noResponseReceived",
            description="Specifies whether a response was received from the server.",
        ),
    ] = False
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the response."
        ),
    ] = None


class Artifact(BaseModel):
    """A single artifact. In some cases, this artifact might be nested within another artifact."""

    model_config = ConfigDict(
        extra="forbid",
    )
    description: Annotated[
        Message | None, Field(description="A short description of the artifact.")
    ] = None
    location: Annotated[
        ArtifactLocation | None, Field(description="The location of the artifact.")
    ] = None
    parent_index: Annotated[
        int | None,
        Field(
            alias="parentIndex",
            description="Identifies the index of the immediate parent of the artifact, if this artifact is nested.",
            ge=-1,
        ),
    ] = -1
    offset: Annotated[
        int | None,
        Field(
            description="The offset in bytes of the artifact within its containing artifact.",
            ge=0,
        ),
    ] = None
    length: Annotated[
        int | None, Field(description="The length of the artifact in bytes.", ge=-1)
    ] = -1
    roles: Annotated[
        list[
            Literal[
                "analysisTarget",
                "attachment",
                "responseFile",
                "resultFile",
                "standardStream",
                "tracedFile",
                "unmodified",
                "modified",
                "added",
                "deleted",
                "renamed",
                "uncontrolled",
                "driver",
                "extension",
                "translation",
                "taxonomy",
                "policy",
                "referencedOnCommandLine",
                "memoryContents",
                "directory",
                "userSpecifiedConfiguration",
                "toolSpecifiedConfiguration",
                "debugOutputFile",
            ]
        ]
        | None,
        Field(
            description="The role or roles played by the artifact in the analysis.",
            min_length=0,
        ),
    ] = []
    mime_type: Annotated[
        str | None,
        Field(
            alias="mimeType",
            description="The MIME type (RFC 2045) of the artifact.",
            pattern="[^/]+/.+",
        ),
    ] = None
    contents: Annotated[
        ArtifactContent | None, Field(description="The contents of the artifact.")
    ] = None
    encoding: Annotated[
        str | None,
        Field(
            description="Specifies the encoding for an artifact object that refers to a text file."
        ),
    ] = None
    source_language: Annotated[
        str | None,
        Field(
            alias="sourceLanguage",
            description="Specifies the source language for any artifact object that refers to a text file that contains source code.",
        ),
    ] = None
    hashes: Annotated[
        dict[str, str] | None,
        Field(
            description="A dictionary, each of whose keys is the name of a hash function and each of whose values is the hashed value of the artifact produced by the specified hash function."
        ),
    ] = None
    last_modified_time_utc: Annotated[
        AwareDatetime | None,
        Field(
            alias="lastModifiedTimeUtc",
            description='The Coordinated Universal Time (UTC) date and time at which the artifact was most recently modified. See "Date/time properties" in the SARIF spec for the required format.',
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the artifact."
        ),
    ] = None


class ArtifactChange(BaseModel):
    """A change to a single artifact."""

    model_config = ConfigDict(
        extra="forbid",
    )
    artifact_location: Annotated[
        ArtifactLocation,
        Field(
            alias="artifactLocation",
            description="The location of the artifact to change.",
        ),
    ]
    replacements: Annotated[
        list[Replacement],
        Field(
            description="An array of replacement objects, each of which represents the replacement of a single region in a single artifact specified by 'artifactLocation'.",
            min_length=1,
        ),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the change."
        ),
    ] = None


class Attachment(BaseModel):
    """An artifact relevant to a result."""

    model_config = ConfigDict(
        extra="forbid",
    )
    description: Annotated[
        Message | None,
        Field(description="A message describing the role played by the attachment."),
    ] = None
    artifact_location: Annotated[
        ArtifactLocation,
        Field(alias="artifactLocation", description="The location of the attachment."),
    ]
    regions: Annotated[
        list[Region] | None,
        Field(
            default_factory=list,
            description="An array of regions of interest within the attachment.",
            min_length=0,
        ),
    ]
    rectangles: Annotated[
        list[Rectangle] | None,
        Field(
            default_factory=list,
            description="An array of rectangles specifying areas of interest within the image.",
            min_length=0,
        ),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the attachment."
        ),
    ] = None


class Fix(BaseModel):
    """A proposed fix for the problem represented by a result object. A fix specifies a set of artifacts to modify. For each artifact, it specifies a set of bytes to remove, and provides a set of new bytes to replace them."""

    model_config = ConfigDict(
        extra="forbid",
    )
    description: Annotated[
        Message | None,
        Field(
            description="A message that describes the proposed fix, enabling viewers to present the proposed change to an end user."
        ),
    ] = None
    artifact_changes: Annotated[
        list[ArtifactChange],
        Field(
            alias="artifactChanges",
            description="One or more artifact changes that comprise a fix for a result.",
            min_length=1,
        ),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the fix."
        ),
    ] = None


class PhysicalLocation1(BaseModel):
    """A physical location relevant to a result. Specifies a reference to a programming artifact together with a range of bytes or characters within that artifact."""

    model_config = ConfigDict(
        extra="forbid",
    )
    address: Annotated[Address, Field(description="The address of the location.")]
    artifact_location: Annotated[
        ArtifactLocation | None,
        Field(alias="artifactLocation", description="The location of the artifact."),
    ] = None
    region: Annotated[
        Region | None, Field(description="Specifies a portion of the artifact.")
    ] = None
    context_region: Annotated[
        Region | None,
        Field(
            alias="contextRegion",
            description="Specifies a portion of the artifact that encloses the region. Allows a viewer to display additional context around the region.",
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the physical location."
        ),
    ] = None


class PhysicalLocation2(BaseModel):
    """A physical location relevant to a result. Specifies a reference to a programming artifact together with a range of bytes or characters within that artifact."""

    model_config = ConfigDict(
        extra="forbid",
    )
    address: Annotated[
        Address | None, Field(description="The address of the location.")
    ] = None
    artifact_location: Annotated[
        ArtifactLocation,
        Field(alias="artifactLocation", description="The location of the artifact."),
    ]
    region: Annotated[
        Region | None, Field(description="Specifies a portion of the artifact.")
    ] = None
    context_region: Annotated[
        Region | None,
        Field(
            alias="contextRegion",
            description="Specifies a portion of the artifact that encloses the region. Allows a viewer to display additional context around the region.",
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the physical location."
        ),
    ] = None


PhysicalLocation = RootModel[PhysicalLocation1 | PhysicalLocation2]


class ResultProvenance(BaseModel):
    """Contains information about how and when a result was detected."""

    model_config = ConfigDict(
        extra="forbid",
    )
    first_detection_time_utc: Annotated[
        AwareDatetime | None,
        Field(
            alias="firstDetectionTimeUtc",
            description='The Coordinated Universal Time (UTC) date and time at which the result was first detected. See "Date/time properties" in the SARIF spec for the required format.',
        ),
    ] = None
    last_detection_time_utc: Annotated[
        AwareDatetime | None,
        Field(
            alias="lastDetectionTimeUtc",
            description='The Coordinated Universal Time (UTC) date and time at which the result was most recently detected. See "Date/time properties" in the SARIF spec for the required format.',
        ),
    ] = None
    first_detection_run_guid: Annotated[
        str | None,
        Field(
            alias="firstDetectionRunGuid",
            description="A GUID-valued string equal to the automationDetails.guid property of the run in which the result was first detected.",
            pattern="^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        ),
    ] = None
    last_detection_run_guid: Annotated[
        str | None,
        Field(
            alias="lastDetectionRunGuid",
            description="A GUID-valued string equal to the automationDetails.guid property of the run in which the result was most recently detected.",
            pattern="^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        ),
    ] = None
    invocation_index: Annotated[
        int | None,
        Field(
            alias="invocationIndex",
            description="The index within the run.invocations array of the invocation object which describes the tool invocation that detected the result.",
            ge=-1,
        ),
    ] = -1
    conversion_sources: Annotated[
        list[PhysicalLocation] | None,
        Field(
            default_factory=list,
            alias="conversionSources",
            description="An array of physicalLocation objects which specify the portions of an analysis tool's output that a converter transformed into the result.",
            min_length=0,
        ),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the result."
        ),
    ] = None


class Tool(BaseModel):
    """The analysis tool that was run."""

    model_config = ConfigDict(
        extra="forbid",
    )
    driver: Annotated[
        ToolComponent, Field(description="The analysis tool that was run.")
    ]
    extensions: Annotated[
        list[ToolComponent] | None,
        Field(
            default_factory=list,
            description="Tool extensions that contributed to or reconfigured the analysis tool that was run.",
            min_length=0,
        ),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the tool."
        ),
    ] = None


class Location(BaseModel):
    """A location within a programming artifact."""

    model_config = ConfigDict(
        extra="forbid",
    )
    id: Annotated[
        int | None,
        Field(
            description="Value that distinguishes this location from all other locations within a single result object.",
            ge=-1,
        ),
    ] = -1
    physical_location: Annotated[
        PhysicalLocation | None,
        Field(
            alias="physicalLocation", description="Identifies the artifact and region."
        ),
    ] = None
    logical_locations: Annotated[
        list[LogicalLocation] | None,
        Field(
            default_factory=list,
            alias="logicalLocations",
            description="The logical locations associated with the result.",
            min_length=0,
        ),
    ]
    message: Annotated[
        Message | None, Field(description="A message relevant to the location.")
    ] = None
    annotations: Annotated[
        list[Region] | None,
        Field(
            default_factory=list,
            description="A set of regions relevant to the location.",
            min_length=0,
        ),
    ]
    relationships: Annotated[
        list[LocationRelationship] | None,
        Field(
            default_factory=list,
            description="An array of objects that describe relationships between this location and others.",
            min_length=0,
        ),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the location."
        ),
    ] = None


class Node(BaseModel):
    """Represents a node in a graph."""

    model_config = ConfigDict(
        extra="forbid",
    )
    id: Annotated[
        str,
        Field(
            description="A string that uniquely identifies the node within its graph."
        ),
    ]
    label: Annotated[
        Message | None, Field(description="A short description of the node.")
    ] = None
    location: Annotated[
        Location | None, Field(description="A code location associated with the node.")
    ] = None
    children: Annotated[
        list[Node] | None,
        Field(default_factory=list, description="Array of child nodes."),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the node."
        ),
    ] = None


class StackFrame(BaseModel):
    """A function call within a stack trace."""

    model_config = ConfigDict(
        extra="forbid",
    )
    location: Annotated[
        Location | None,
        Field(description="The location to which this stack frame refers."),
    ] = None
    module: Annotated[
        str | None,
        Field(
            description="The name of the module that contains the code of this stack frame."
        ),
    ] = None
    thread_id: Annotated[
        int | None,
        Field(
            alias="threadId", description="The thread identifier of the stack frame."
        ),
    ] = None
    parameters: Annotated[
        list[str] | None,
        Field(
            description="The parameters of the call that is executing.", min_length=0
        ),
    ] = []
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the stack frame."
        ),
    ] = None


class Suppression(BaseModel):
    """A suppression that is relevant to a result."""

    model_config = ConfigDict(
        extra="forbid",
    )
    guid: Annotated[
        str | None,
        Field(
            description="A stable, unique identifer for the suprression in the form of a GUID.",
            pattern="^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        ),
    ] = None
    kind: Annotated[
        Literal["inSource", "external"],
        Field(
            description="A string that indicates where the suppression is persisted."
        ),
    ]
    state: Annotated[
        Literal["accepted", "underReview", "rejected"] | None,
        Field(description="A string that indicates the state of the suppression."),
    ] = None
    justification: Annotated[
        str | None,
        Field(
            description="A string representing the justification for the suppression."
        ),
    ] = None
    location: Annotated[
        Location | None,
        Field(description="Identifies the location associated with the suppression."),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the suppression."
        ),
    ] = None


class Graph(BaseModel):
    """A network of nodes and directed edges that describes some aspect of the structure of the code (for example, a call graph)."""

    model_config = ConfigDict(
        extra="forbid",
    )
    description: Annotated[
        Message | None, Field(description="A description of the graph.")
    ] = None
    nodes: Annotated[
        list[Node] | None,
        Field(
            default_factory=list,
            description="An array of node objects representing the nodes of the graph.",
            min_length=0,
        ),
    ]
    edges: Annotated[
        list[Edge] | None,
        Field(
            default_factory=list,
            description="An array of edge objects representing the edges of the graph.",
            min_length=0,
        ),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the graph."
        ),
    ] = None


class Stack(BaseModel):
    """A call stack that is relevant to a result."""

    model_config = ConfigDict(
        extra="forbid",
    )
    message: Annotated[
        Message | None, Field(description="A message relevant to this call stack.")
    ] = None
    frames: Annotated[
        list[StackFrame],
        Field(
            description="An array of stack frames that represents a sequence of calls, rendered in reverse chronological order, that comprise the call stack.",
            min_length=0,
        ),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the stack."
        ),
    ] = None


class ThreadFlowLocation(BaseModel):
    """A location visited by an analysis tool while simulating or monitoring the execution of a program."""

    model_config = ConfigDict(
        extra="forbid",
    )
    index: Annotated[
        int | None,
        Field(description="The index within the run threadFlowLocations array.", ge=-1),
    ] = -1
    location: Annotated[Location | None, Field(description="The code location.")] = None
    stack: Annotated[
        Stack | None, Field(description="The call stack leading to this location.")
    ] = None
    kinds: Annotated[
        list[str] | None,
        Field(
            description="A set of distinct strings that categorize the thread flow location. Well-known kinds include 'acquire', 'release', 'enter', 'exit', 'call', 'return', 'branch', 'implicit', 'false', 'true', 'caution', 'danger', 'unknown', 'unreachable', 'taint', 'function', 'handler', 'lock', 'memory', 'resource', 'scope' and 'value'.",
            min_length=0,
        ),
    ] = []
    taxa: Annotated[
        list[ReportingDescriptorReference] | None,
        Field(
            default_factory=list,
            description="An array of references to rule or taxonomy reporting descriptors that are applicable to the thread flow location.",
            min_length=0,
        ),
    ]
    module: Annotated[
        str | None,
        Field(
            description="The name of the module that contains the code that is executing."
        ),
    ] = None
    state: Annotated[
        dict[str, MultiformatMessageString] | None,
        Field(
            description="A dictionary, each of whose keys specifies a variable or expression, the associated value of which represents the variable or expression value. For an annotation of kind 'continuation', for example, this dictionary might hold the current assumed values of a set of global variables."
        ),
    ] = None
    nesting_level: Annotated[
        int | None,
        Field(
            alias="nestingLevel",
            description="An integer representing a containment hierarchy within the thread flow.",
            ge=0,
        ),
    ] = None
    execution_order: Annotated[
        int | None,
        Field(
            alias="executionOrder",
            description="An integer representing the temporal order in which execution reached this location.",
            ge=-1,
        ),
    ] = -1
    execution_time_utc: Annotated[
        AwareDatetime | None,
        Field(
            alias="executionTimeUtc",
            description="The Coordinated Universal Time (UTC) date and time at which this location was executed.",
        ),
    ] = None
    importance: Annotated[
        Literal["important", "essential", "unimportant"] | None,
        Field(
            description='Specifies the importance of this location in understanding the code flow in which it occurs. The order from most to least important is "essential", "important", "unimportant". Default: "important".'
        ),
    ] = "important"
    web_request: Annotated[
        WebRequest | None,
        Field(
            alias="webRequest",
            description="A web request associated with this thread flow location.",
        ),
    ] = None
    web_response: Annotated[
        WebResponse | None,
        Field(
            alias="webResponse",
            description="A web response associated with this thread flow location.",
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the threadflow location."
        ),
    ] = None


class Exception(BaseModel):
    """Describes a runtime exception encountered during the execution of an analysis tool."""

    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Annotated[
        str | None,
        Field(
            description="A string that identifies the kind of exception, for example, the fully qualified type name of an object that was thrown, or the symbolic name of a signal."
        ),
    ] = None
    message: Annotated[
        str | None, Field(description="A message that describes the exception.")
    ] = None
    stack: Annotated[
        Stack | None,
        Field(description="The sequence of function calls leading to the exception."),
    ] = None
    inner_exceptions: Annotated[
        list[Exception] | None,
        Field(
            default_factory=list,
            alias="innerExceptions",
            description="An array of exception objects each of which is considered a cause of this exception.",
        ),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the exception."
        ),
    ] = None


class Notification(BaseModel):
    """Describes a condition relevant to the tool itself, as opposed to being relevant to a target being analyzed by the tool."""

    model_config = ConfigDict(
        extra="forbid",
    )
    locations: Annotated[
        list[Location] | None,
        Field(
            default_factory=list,
            description="The locations relevant to this notification.",
            min_length=0,
        ),
    ]
    message: Annotated[
        Message,
        Field(
            description="A message that describes the condition that was encountered."
        ),
    ]
    level: Annotated[
        Literal["none", "note", "warning", "error"] | None,
        Field(description="A value specifying the severity level of the notification."),
    ] = "warning"
    thread_id: Annotated[
        int | None,
        Field(
            alias="threadId",
            description="The thread identifier of the code that generated the notification.",
        ),
    ] = None
    time_utc: Annotated[
        AwareDatetime | None,
        Field(
            alias="timeUtc",
            description="The Coordinated Universal Time (UTC) date and time at which the analysis tool generated the notification.",
        ),
    ] = None
    exception: Annotated[
        Exception | None,
        Field(
            description="The runtime exception, if any, relevant to this notification."
        ),
    ] = None
    descriptor: Annotated[
        ReportingDescriptorReference | None,
        Field(
            description="A reference used to locate the descriptor relevant to this notification."
        ),
    ] = None
    associated_rule: Annotated[
        ReportingDescriptorReference | None,
        Field(
            alias="associatedRule",
            description="A reference used to locate the rule descriptor associated with this notification.",
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the notification."
        ),
    ] = None


class ThreadFlow(BaseModel):
    """Describes a sequence of code locations that specify a path through a single thread of execution such as an operating system or fiber."""

    model_config = ConfigDict(
        extra="forbid",
    )
    id: Annotated[
        str | None,
        Field(
            description="An string that uniquely identifies the threadFlow within the codeFlow in which it occurs."
        ),
    ] = None
    message: Annotated[
        Message | None, Field(description="A message relevant to the thread flow.")
    ] = None
    initial_state: Annotated[
        dict[str, MultiformatMessageString] | None,
        Field(
            alias="initialState",
            description="Values of relevant expressions at the start of the thread flow that may change during thread flow execution.",
        ),
    ] = None
    immutable_state: Annotated[
        dict[str, MultiformatMessageString] | None,
        Field(
            alias="immutableState",
            description="Values of relevant expressions at the start of the thread flow that remain constant.",
        ),
    ] = None
    locations: Annotated[
        list[ThreadFlowLocation],
        Field(
            description="A temporally ordered array of 'threadFlowLocation' objects, each of which describes a location visited by the tool while producing the result.",
            min_length=1,
        ),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the thread flow."
        ),
    ] = None


class CodeFlow(BaseModel):
    """A set of threadFlows which together describe a pattern of code execution relevant to detecting a result."""

    model_config = ConfigDict(
        extra="forbid",
    )
    message: Annotated[
        Message | None, Field(description="A message relevant to the code flow.")
    ] = None
    thread_flows: Annotated[
        list[ThreadFlow],
        Field(
            alias="threadFlows",
            description="An array of one or more unique threadFlow objects, each of which describes the progress of a program through a thread of execution.",
            min_length=1,
        ),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the code flow."
        ),
    ] = None


class Invocation(BaseModel):
    """The runtime environment of the analysis tool run."""

    model_config = ConfigDict(
        extra="forbid",
    )
    command_line: Annotated[
        str | None,
        Field(
            alias="commandLine", description="The command line used to invoke the tool."
        ),
    ] = None
    arguments: Annotated[
        list[str] | None,
        Field(
            description="An array of strings, containing in order the command line arguments passed to the tool from the operating system.",
            min_length=0,
        ),
    ] = None
    response_files: Annotated[
        list[ArtifactLocation] | None,
        Field(
            alias="responseFiles",
            description="The locations of any response files specified on the tool's command line.",
            min_length=0,
        ),
    ] = None
    start_time_utc: Annotated[
        AwareDatetime | None,
        Field(
            alias="startTimeUtc",
            description='The Coordinated Universal Time (UTC) date and time at which the run started. See "Date/time properties" in the SARIF spec for the required format.',
        ),
    ] = None
    end_time_utc: Annotated[
        AwareDatetime | None,
        Field(
            alias="endTimeUtc",
            description='The Coordinated Universal Time (UTC) date and time at which the run ended. See "Date/time properties" in the SARIF spec for the required format.',
        ),
    ] = None
    exit_code: Annotated[
        int | None, Field(alias="exitCode", description="The process exit code.")
    ] = None
    rule_configuration_overrides: Annotated[
        list[ConfigurationOverride] | None,
        Field(
            default_factory=list,
            alias="ruleConfigurationOverrides",
            description="An array of configurationOverride objects that describe rules related runtime overrides.",
            min_length=0,
        ),
    ]
    notification_configuration_overrides: Annotated[
        list[ConfigurationOverride] | None,
        Field(
            default_factory=list,
            alias="notificationConfigurationOverrides",
            description="An array of configurationOverride objects that describe notifications related runtime overrides.",
            min_length=0,
        ),
    ]
    tool_execution_notifications: Annotated[
        list[Notification] | None,
        Field(
            default_factory=list,
            alias="toolExecutionNotifications",
            description="A list of runtime conditions detected by the tool during the analysis.",
            min_length=0,
        ),
    ]
    tool_configuration_notifications: Annotated[
        list[Notification] | None,
        Field(
            default_factory=list,
            alias="toolConfigurationNotifications",
            description="A list of conditions detected by the tool that are relevant to the tool's configuration.",
            min_length=0,
        ),
    ]
    exit_code_description: Annotated[
        str | None,
        Field(
            alias="exitCodeDescription", description="The reason for the process exit."
        ),
    ] = None
    exit_signal_name: Annotated[
        str | None,
        Field(
            alias="exitSignalName",
            description="The name of the signal that caused the process to exit.",
        ),
    ] = None
    exit_signal_number: Annotated[
        int | None,
        Field(
            alias="exitSignalNumber",
            description="The numeric value of the signal that caused the process to exit.",
        ),
    ] = None
    process_start_failure_message: Annotated[
        str | None,
        Field(
            alias="processStartFailureMessage",
            description="The reason given by the operating system that the process failed to start.",
        ),
    ] = None
    execution_successful: Annotated[
        bool,
        Field(
            alias="executionSuccessful",
            description="Specifies whether the tool's execution completed successfully.",
        ),
    ]
    machine: Annotated[
        str | None, Field(description="The machine that hosted the analysis tool run.")
    ] = None
    account: Annotated[
        str | None, Field(description="The account that ran the analysis tool.")
    ] = None
    process_id: Annotated[
        int | None,
        Field(
            alias="processId", description="The process id for the analysis tool run."
        ),
    ] = None
    executable_location: Annotated[
        ArtifactLocation | None,
        Field(
            alias="executableLocation",
            description="An absolute URI specifying the location of the analysis tool's executable.",
        ),
    ] = None
    working_directory: Annotated[
        ArtifactLocation | None,
        Field(
            alias="workingDirectory",
            description="The working directory for the analysis tool run.",
        ),
    ] = None
    environment_variables: Annotated[
        dict[str, str] | None,
        Field(
            alias="environmentVariables",
            description="The environment variables associated with the analysis tool process, expressed as key/value pairs.",
        ),
    ] = None
    stdin: Annotated[
        ArtifactLocation | None,
        Field(
            description="A file containing the standard input stream to the process that was invoked."
        ),
    ] = None
    stdout: Annotated[
        ArtifactLocation | None,
        Field(
            description="A file containing the standard output stream from the process that was invoked."
        ),
    ] = None
    stderr: Annotated[
        ArtifactLocation | None,
        Field(
            description="A file containing the standard error stream from the process that was invoked."
        ),
    ] = None
    stdout_stderr: Annotated[
        ArtifactLocation | None,
        Field(
            alias="stdoutStderr",
            description="A file containing the interleaved standard output and standard error stream from the process that was invoked.",
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the invocation."
        ),
    ] = None


class Result(BaseModel):
    """A result produced by an analysis tool."""

    model_config = ConfigDict(
        extra="forbid",
    )
    rule_id: Annotated[
        str | None,
        Field(
            alias="ruleId",
            description="The stable, unique identifier of the rule, if any, to which this notification is relevant. This member can be used to retrieve rule metadata from the rules dictionary, if it exists.",
        ),
    ] = None
    rule_index: Annotated[
        int | None,
        Field(
            alias="ruleIndex",
            description="The index within the tool component rules array of the rule object associated with this result.",
            ge=-1,
        ),
    ] = -1
    rule: Annotated[
        ReportingDescriptorReference | None,
        Field(
            description="A reference used to locate the rule descriptor relevant to this result."
        ),
    ] = None
    kind: Annotated[
        Literal["notApplicable", "pass", "fail", "review", "open", "informational"]
        | None,
        Field(description="A value that categorizes results by evaluation state."),
    ] = "fail"
    level: Annotated[
        Literal["none", "note", "warning", "error"] | None,
        Field(description="A value specifying the severity level of the result."),
    ] = "warning"
    message: Annotated[
        Message,
        Field(
            description="A message that describes the result. The first sentence of the message only will be displayed when visible space is limited."
        ),
    ]
    analysis_target: Annotated[
        ArtifactLocation | None,
        Field(
            alias="analysisTarget",
            description="Identifies the artifact that the analysis tool was instructed to scan. This need not be the same as the artifact where the result actually occurred.",
        ),
    ] = None
    locations: Annotated[
        list[Location] | None,
        Field(
            default_factory=list,
            description="The set of locations where the result was detected. Specify only one location unless the problem indicated by the result can only be corrected by making a change at every specified location.",
            min_length=0,
        ),
    ]
    guid: Annotated[
        str | None,
        Field(
            description="A stable, unique identifer for the result in the form of a GUID.",
            pattern="^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        ),
    ] = None
    correlation_guid: Annotated[
        str | None,
        Field(
            alias="correlationGuid",
            description="A stable, unique identifier for the equivalence class of logically identical results to which this result belongs, in the form of a GUID.",
            pattern="^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        ),
    ] = None
    occurrence_count: Annotated[
        int | None,
        Field(
            alias="occurrenceCount",
            description="A positive integer specifying the number of times this logically unique result was observed in this run.",
            ge=1,
        ),
    ] = None
    partial_fingerprints: Annotated[
        dict[str, str] | None,
        Field(
            alias="partialFingerprints",
            description="A set of strings that contribute to the stable, unique identity of the result.",
        ),
    ] = None
    fingerprints: Annotated[
        dict[str, str] | None,
        Field(
            description="A set of strings each of which individually defines a stable, unique identity for the result."
        ),
    ] = None
    stacks: Annotated[
        list[Stack] | None,
        Field(
            default_factory=list,
            description="An array of 'stack' objects relevant to the result.",
            min_length=0,
        ),
    ]
    code_flows: Annotated[
        list[CodeFlow] | None,
        Field(
            default_factory=list,
            alias="codeFlows",
            description="An array of 'codeFlow' objects relevant to the result.",
            min_length=0,
        ),
    ]
    graphs: Annotated[
        list[Graph] | None,
        Field(
            default_factory=list,
            description="An array of zero or more unique graph objects associated with the result.",
            min_length=0,
        ),
    ]
    graph_traversals: Annotated[
        list[GraphTraversal] | None,
        Field(
            default_factory=list,
            alias="graphTraversals",
            description="An array of one or more unique 'graphTraversal' objects.",
            min_length=0,
        ),
    ]
    related_locations: Annotated[
        list[Location] | None,
        Field(
            default_factory=list,
            alias="relatedLocations",
            description="A set of locations relevant to this result.",
            min_length=0,
        ),
    ]
    suppressions: Annotated[
        list[Suppression] | None,
        Field(
            description="A set of suppressions relevant to this result.", min_length=0
        ),
    ] = None
    baseline_state: Annotated[
        Literal["new", "unchanged", "updated", "absent"] | None,
        Field(
            alias="baselineState",
            description="The state of a result relative to a baseline of a previous run.",
        ),
    ] = None
    rank: Annotated[
        float | None,
        Field(
            description="A number representing the priority or importance of the result.",
            ge=-1.0,
            le=100.0,
        ),
    ] = -1.0
    attachments: Annotated[
        list[Attachment] | None,
        Field(
            default_factory=list,
            description="A set of artifacts relevant to the result.",
            min_length=0,
        ),
    ]
    hosted_viewer_uri: Annotated[
        AnyUrl | None,
        Field(
            alias="hostedViewerUri",
            description="An absolute URI at which the result can be viewed.",
        ),
    ] = None
    work_item_uris: Annotated[
        list[AnyUrl] | None,
        Field(
            alias="workItemUris",
            description="The URIs of the work items associated with this result.",
        ),
    ] = None
    provenance: Annotated[
        ResultProvenance | None,
        Field(description="Information about how and when the result was detected."),
    ] = None
    fixes: Annotated[
        list[Fix] | None,
        Field(
            default_factory=list,
            description="An array of 'fix' objects, each of which represents a proposed fix to the problem indicated by the result.",
            min_length=0,
        ),
    ]
    taxa: Annotated[
        list[ReportingDescriptorReference] | None,
        Field(
            default_factory=list,
            description="An array of references to taxonomy reporting descriptors that are applicable to the result.",
            min_length=0,
        ),
    ]
    web_request: Annotated[
        WebRequest | None,
        Field(
            alias="webRequest", description="A web request associated with this result."
        ),
    ] = None
    web_response: Annotated[
        WebResponse | None,
        Field(
            alias="webResponse",
            description="A web response associated with this result.",
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the result."
        ),
    ] = None


class Conversion(BaseModel):
    """Describes how a converter transformed the output of a static analysis tool from the analysis tool's native output format into the SARIF format."""

    model_config = ConfigDict(
        extra="forbid",
    )
    tool: Annotated[
        Tool, Field(description="A tool object that describes the converter.")
    ]
    invocation: Annotated[
        Invocation | None,
        Field(
            description="An invocation object that describes the invocation of the converter."
        ),
    ] = None
    analysis_tool_log_files: Annotated[
        list[ArtifactLocation] | None,
        Field(
            default_factory=list,
            alias="analysisToolLogFiles",
            description="The locations of the analysis tool's per-run log files.",
            min_length=0,
        ),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the conversion."
        ),
    ] = None


class ExternalProperties(BaseModel):
    """The top-level element of an external property file."""

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Annotated[
        AnyUrl | None,
        Field(
            alias="schema",
            description="The URI of the JSON schema corresponding to the version of the external property file format.",
        ),
    ] = None
    version: Annotated[
        Literal["2.1.0"] | None,
        Field(
            description="The SARIF format version of this external properties object."
        ),
    ] = None
    guid: Annotated[
        str | None,
        Field(
            description="A stable, unique identifer for this external properties object, in the form of a GUID.",
            pattern="^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        ),
    ] = None
    run_guid: Annotated[
        str | None,
        Field(
            alias="runGuid",
            description="A stable, unique identifer for the run associated with this external properties object, in the form of a GUID.",
            pattern="^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        ),
    ] = None
    conversion: Annotated[
        Conversion | None,
        Field(
            description="A conversion object that will be merged with a separate run."
        ),
    ] = None
    graphs: Annotated[
        list[Graph] | None,
        Field(
            default_factory=list,
            description="An array of graph objects that will be merged with a separate run.",
            min_length=0,
        ),
    ]
    externalized_properties: Annotated[
        PropertyBag | None,
        Field(
            alias="externalizedProperties",
            description="Key/value pairs that provide additional information that will be merged with a separate run.",
        ),
    ] = None
    artifacts: Annotated[
        list[Artifact] | None,
        Field(
            description="An array of artifact objects that will be merged with a separate run.",
            min_length=0,
        ),
    ] = None
    invocations: Annotated[
        list[Invocation] | None,
        Field(
            default_factory=list,
            description="Describes the invocation of the analysis tool that will be merged with a separate run.",
            min_length=0,
        ),
    ]
    logical_locations: Annotated[
        list[LogicalLocation] | None,
        Field(
            default_factory=list,
            alias="logicalLocations",
            description="An array of logical locations such as namespaces, types or functions that will be merged with a separate run.",
            min_length=0,
        ),
    ]
    thread_flow_locations: Annotated[
        list[ThreadFlowLocation] | None,
        Field(
            default_factory=list,
            alias="threadFlowLocations",
            description="An array of threadFlowLocation objects that will be merged with a separate run.",
            min_length=0,
        ),
    ]
    results: Annotated[
        list[Result] | None,
        Field(
            default_factory=list,
            description="An array of result objects that will be merged with a separate run.",
            min_length=0,
        ),
    ]
    taxonomies: Annotated[
        list[ToolComponent] | None,
        Field(
            default_factory=list,
            description="Tool taxonomies that will be merged with a separate run.",
            min_length=0,
        ),
    ]
    driver: Annotated[
        ToolComponent | None,
        Field(
            description="The analysis tool object that will be merged with a separate run."
        ),
    ] = None
    extensions: Annotated[
        list[ToolComponent] | None,
        Field(
            default_factory=list,
            description="Tool extensions that will be merged with a separate run.",
            min_length=0,
        ),
    ]
    policies: Annotated[
        list[ToolComponent] | None,
        Field(
            default_factory=list,
            description="Tool policies that will be merged with a separate run.",
            min_length=0,
        ),
    ]
    translations: Annotated[
        list[ToolComponent] | None,
        Field(
            default_factory=list,
            description="Tool translations that will be merged with a separate run.",
            min_length=0,
        ),
    ]
    addresses: Annotated[
        list[Address] | None,
        Field(
            default_factory=list,
            description="Addresses that will be merged with a separate run.",
            min_length=0,
        ),
    ]
    web_requests: Annotated[
        list[WebRequest] | None,
        Field(
            default_factory=list,
            alias="webRequests",
            description="Requests that will be merged with a separate run.",
            min_length=0,
        ),
    ]
    web_responses: Annotated[
        list[WebResponse] | None,
        Field(
            default_factory=list,
            alias="webResponses",
            description="Responses that will be merged with a separate run.",
            min_length=0,
        ),
    ]
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the external properties."
        ),
    ] = None


class Run(BaseModel):
    """Describes a single run of an analysis tool, and contains the reported output of that run."""

    model_config = ConfigDict(
        extra="forbid",
    )
    tool: Annotated[
        Tool,
        Field(
            description="Information about the tool or tool pipeline that generated the results in this run. A run can only contain results produced by a single tool or tool pipeline. A run can aggregate results from multiple log files, as long as context around the tool run (tool command-line arguments and the like) is identical for all aggregated files."
        ),
    ]
    invocations: Annotated[
        list[Invocation] | None,
        Field(
            default_factory=list,
            description="Describes the invocation of the analysis tool.",
            min_length=0,
        ),
    ]
    conversion: Annotated[
        Conversion | None,
        Field(
            description="A conversion object that describes how a converter transformed an analysis tool's native reporting format into the SARIF format."
        ),
    ] = None
    language: Annotated[
        str | None,
        Field(
            description="The language of the messages emitted into the log file during this run (expressed as an ISO 639-1 two-letter lowercase culture code) and an optional region (expressed as an ISO 3166-1 two-letter uppercase subculture code associated with a country or region). The casing is recommended but not required (in order for this data to conform to RFC5646).",
            pattern="^[a-zA-Z]{2}|^[a-zA-Z]{2}-[a-zA-Z]{2}]?$",
        ),
    ] = "en-US"
    version_control_provenance: Annotated[
        list[VersionControlDetails] | None,
        Field(
            default_factory=list,
            alias="versionControlProvenance",
            description="Specifies the revision in version control of the artifacts that were scanned.",
            min_length=0,
        ),
    ]
    original_uri_base_ids: Annotated[
        dict[str, ArtifactLocation] | None,
        Field(
            alias="originalUriBaseIds",
            description="The artifact location specified by each uriBaseId symbol on the machine where the tool originally ran.",
        ),
    ] = None
    artifacts: Annotated[
        list[Artifact] | None,
        Field(
            description="An array of artifact objects relevant to the run.",
            min_length=0,
        ),
    ] = None
    logical_locations: Annotated[
        list[LogicalLocation] | None,
        Field(
            default_factory=list,
            alias="logicalLocations",
            description="An array of logical locations such as namespaces, types or functions.",
            min_length=0,
        ),
    ]
    graphs: Annotated[
        list[Graph] | None,
        Field(
            default_factory=list,
            description="An array of zero or more unique graph objects associated with the run.",
            min_length=0,
        ),
    ]
    results: Annotated[
        list[Result] | None,
        Field(
            description="The set of results contained in an SARIF log. The results array can be omitted when a run is solely exporting rules metadata. It must be present (but may be empty) if a log file represents an actual scan.",
            min_length=0,
        ),
    ] = None
    automation_details: Annotated[
        RunAutomationDetails | None,
        Field(
            alias="automationDetails",
            description="Automation details that describe this run.",
        ),
    ] = None
    run_aggregates: Annotated[
        list[RunAutomationDetails] | None,
        Field(
            default_factory=list,
            alias="runAggregates",
            description="Automation details that describe the aggregate of runs to which this run belongs.",
            min_length=0,
        ),
    ]
    baseline_guid: Annotated[
        str | None,
        Field(
            alias="baselineGuid",
            description="The 'guid' property of a previous SARIF 'run' that comprises the baseline that was used to compute result 'baselineState' properties for the run.",
            pattern="^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        ),
    ] = None
    redaction_tokens: Annotated[
        list[str] | None,
        Field(
            alias="redactionTokens",
            description="An array of strings used to replace sensitive information in a redaction-aware property.",
            min_length=0,
        ),
    ] = []
    default_encoding: Annotated[
        str | None,
        Field(
            alias="defaultEncoding",
            description="Specifies the default encoding for any artifact object that refers to a text file.",
        ),
    ] = None
    default_source_language: Annotated[
        str | None,
        Field(
            alias="defaultSourceLanguage",
            description="Specifies the default source language for any artifact object that refers to a text file that contains source code.",
        ),
    ] = None
    newline_sequences: Annotated[
        list[str] | None,
        Field(
            alias="newlineSequences",
            description="An ordered list of character sequences that were treated as line breaks when computing region information for the run.",
            min_length=1,
        ),
    ] = ["\r\n", "\n"]
    column_kind: Annotated[
        Literal["utf16CodeUnits", "unicodeCodePoints"] | None,
        Field(
            alias="columnKind",
            description="Specifies the unit in which the tool measures columns.",
        ),
    ] = None
    external_property_file_references: Annotated[
        ExternalPropertyFileReferences | None,
        Field(
            alias="externalPropertyFileReferences",
            description="References to external property files that should be inlined with the content of a root log file.",
        ),
    ] = None
    thread_flow_locations: Annotated[
        list[ThreadFlowLocation] | None,
        Field(
            default_factory=list,
            alias="threadFlowLocations",
            description="An array of threadFlowLocation objects cached at run level.",
            min_length=0,
        ),
    ]
    taxonomies: Annotated[
        list[ToolComponent] | None,
        Field(
            default_factory=list,
            description="An array of toolComponent objects relevant to a taxonomy in which results are categorized.",
            min_length=0,
        ),
    ]
    addresses: Annotated[
        list[Address] | None,
        Field(
            default_factory=list,
            description="Addresses associated with this run instance, if any.",
            min_length=0,
        ),
    ]
    translations: Annotated[
        list[ToolComponent] | None,
        Field(
            default_factory=list,
            description="The set of available translations of the localized data provided by the tool.",
            min_length=0,
        ),
    ]
    policies: Annotated[
        list[ToolComponent] | None,
        Field(
            default_factory=list,
            description="Contains configurations that may potentially override both reportingDescriptor.defaultConfiguration (the tool's default severities) and invocation.configurationOverrides (severities established at run-time from the command line).",
            min_length=0,
        ),
    ]
    web_requests: Annotated[
        list[WebRequest] | None,
        Field(
            default_factory=list,
            alias="webRequests",
            description="An array of request objects cached at run level.",
            min_length=0,
        ),
    ]
    web_responses: Annotated[
        list[WebResponse] | None,
        Field(
            default_factory=list,
            alias="webResponses",
            description="An array of response objects cached at run level.",
            min_length=0,
        ),
    ]
    special_locations: Annotated[
        SpecialLocations | None,
        Field(
            alias="specialLocations",
            description="A specialLocations object that defines locations of special significance to SARIF consumers.",
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the run."
        ),
    ] = None


class StaticAnalysisResultsFormatSarifVersion210JsonSchema(BaseModel):
    """Static Analysis Results Format (SARIF) Version 2.1.0 JSON Schema: a standard format for the output of static analysis tools."""

    model_config = ConfigDict(
        extra="forbid",
    )
    field_schema: Annotated[
        AnyUrl | None,
        Field(
            alias="$schema",
            description="The URI of the JSON schema corresponding to the version.",
        ),
    ] = None
    version: Annotated[
        Literal["2.1.0"],
        Field(description="The SARIF format version of this log file."),
    ]
    runs: Annotated[
        list[Run],
        Field(description="The set of runs contained in this log file.", min_length=0),
    ]
    inline_external_properties: Annotated[
        list[ExternalProperties] | None,
        Field(
            alias="inlineExternalProperties",
            description="References to external property files that share data between runs.",
            min_length=0,
        ),
    ] = None
    properties: Annotated[
        PropertyBag | None,
        Field(
            description="Key/value pairs that provide additional information about the log file."
        ),
    ] = None


Node.model_rebuild()
Exception.model_rebuild()
