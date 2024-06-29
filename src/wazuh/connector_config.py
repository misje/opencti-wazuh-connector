from pydantic_settings import SettingsConfigDict
from .config_base import ConfigBase, FuzzyEnum


# There are five types, but we only support the type that the connector is
# implemented as:
class ConnectorType(FuzzyEnum):
    """
    OpenCTI connector type
    """

    InternalEnrichment = "internal_enrichment"
    """
    :octid:`Internal enrichment <connectors/?h=internal+enrich#enrichment>`,
    then only supported type for this connector
    """


class SupportedEntity(FuzzyEnum):
    """
    The entities that the connector support

    .. seealso::

        See :ref:`supported entities <supported-entities>`.
    """

    Artifact = "Artifact"
    Directory = "Directory"
    DomainName = "Domain-Name"
    EMailAddr = "Email-Addr"
    Hostname = "Hostname"
    IPv4Addr = "IPv4-Addr"
    IPv6Addr = "IPv6-Addr"
    MAC = "Mac-Addr"
    NetworkTraffic = "Network-Traffic"
    Process = "Process"
    Software = "Software"
    StixFile = "StixFile"
    URL = "Url"
    UserAccount = "User-Account"
    UserAgent = "User-Agent"
    WindowsRegistryKey = "WindowsRegistryKey"
    WindowsRegistryValueType = "WindowsRegistryValueType"
    Vulnerability = "Vulnerability"
    Indicator = "Indicator"


class LogLevel(FuzzyEnum):
    """
    Log level
    """

    Debug = "debug"
    """
    Debug, info, warning and error messages
    """
    Info = "info"
    """
    Info, warning and error messages
    """
    Warning = "warning"
    """
    Warning and error messages
    """
    Error = "error"
    """
    Error messages only
    """


class ConnectorConfig(ConfigBase):
    """
    Connector settings

    These settings are the most important settings used by the connector. There
    are other settings supported by the connector API, but they are not listed
    here, nor is there any official documentation for them.
    """

    model_config = SettingsConfigDict(
        env_prefix="CONNECTOR_",
        validate_assignment=True,
        extra="allow",
    )

    id: str
    """
    Connector ID

    This string should be a :term:`UUID`
    """
    # TODO: test any case:
    type: ConnectorType = ConnectorType.InternalEnrichment
    """
    The type of the connector, which must be Enrichment
    """
    name: str = "Wazuh"
    """
    Name used to identify the connector in OpenCTI
    """
    # FIXME: "all" doesn't work (because opencti intercepts this env. variable):
    scope: set[SupportedEntity] = set(SupportedEntity)
    """
    Which entities to enable enrichment for

    This specifies all entities that the connector should be made available for
    enrichment. If an entity is not lsted here, the connector will not show up as
    an option when clicking on the enrichment button in OpenCTI.

    .. seealso::
    
        See :ref:`supported entities <supported-entities>` for supported
        choices.
    """
    auto: bool = True
    """
    Run automatically or manually

    Whether to run the connector automatically whenever an entity in
    *CONNECTOR_SCOPE* is created, or just manually.

    .. seealso:: See :ref:`when to run <when-to-run>` for details.
    """
    log_level: LogLevel = LogLevel.Warning
    """
    Log level

    Set the log level to *warning* or *error* under normal use. Use *debug* when
    troubleshooting and gathering info for an issue.

    .. seealso::

        See how to access logs in :ref:`troubleshooting <search-logs>`
    """
