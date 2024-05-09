from pydantic_settings import SettingsConfigDict
from .config_base import ConfigBase, FuzzyEnum


# There are five types, but we only support the type that the connector is
# implemented as:
class ConnectorType(FuzzyEnum):
    InternalEnrichment = "internal_enrichment"


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
    Debug = "debug"
    Info = "info"
    Warning = "warning"
    Error = "error"


class ConnectorConfig(ConfigBase):
    """
    Helper class to parse the most important OpenCTI connector settings (from
    file)

    This class is not complete, and does not reference all possible
    configuration options. These are still parsed by opencti_connector_helper.py
    as environment vairables.
    """

    model_config = SettingsConfigDict(
        env_prefix="CONNECTOR_",
        validate_assignment=True,
        extra="allow",
    )

    id: str
    """
    Connector ID

    This string should be a UUID
    """
    # TODO: test any case:
    type: ConnectorType = ConnectorType.InternalEnrichment
    """
    The type of the connector, which must be Enrichment
    """
    name: str = "Wazuh"
    """
    The name of the connector
    """
    scope: set[SupportedEntity] = set(SupportedEntity)
    """
    Which entities the connector should enrich

    See :ref:`supported entities <supported-entities>` for details.
    """
    auto: bool = True
    """
    Run automatically or manually

    See :ref:`when to run <when-to-run>` for details.
    """
    log_level: LogLevel = LogLevel.Warning
    """
    Log level
    """
