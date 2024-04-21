import re
from pydantic import (
    AnyUrl,
    AnyHttpUrl,
    Field,
    field_validator,
    ValidationInfo,
)
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Iterable

from .wazuh_api_config import WazuhAPIConfig
from .opensearch_config import OpenSearchConfig
from .enrich_config import EnrichmentConfig
from .stix_helper import TLPLiteral, tlp_marking_from_string, validate_stix_id
from .utils import comma_string_to_set, verify_url
from .config_base import ConfigBase
from enum import Enum


# TODO: test if a member has a union (e.g. TLPLiteral|str), and doesn't have a
# validator that changes the type, that the resulting object has the most
# strong type. If so, add these unions and remove "type:ignore" comments from
# test code


# TODO: add aliases to create sensible env names
# TODO: Use autodoc_pydantic_field_doc_policy=docstring and move and improve
# format of description into docstrings
class Config(ConfigBase):
    """
    FIXME
    """

    model_config = SettingsConfigDict(env_prefix="WAZUH_", validate_assignment=True)

    # TODO: add helper function for parsing without dashes too
    class IncidentCreateMode(Enum):
        """
        How and when incidents should be created

        If :octiu:`incidents <exploring-events/#incidents>` should be created,
        (:py:attr:`~Config.require_indicator_for_incidents` is False or the
        observable has indicators based on it, and the alert rule level equals
        or is greater than :attr:`~Config.create_incident_threshold`), this
        enumerator determines how incidents are created.

        The amount of incidents created for every option is roughly in the
        following order, from the least to the most: :attr:`Never`,
        :attr:`PerQuery`, :attr:`PerSighting`, :attr:`PerAlertRule`,
        :attr:`PerAlert`.
        """

        PerQuery = "per-query"
        """
        An incident is created only once per enrichment/query. This is the least
        noisy option (except for :py:attr:`Never`).
        """
        PerSighting = "per-sighting"
        """
        Create an incident for every :octiu:`sighting <exploring-events/#sightings>`.
        """
        PerAlertRule = "per-alert-rule"
        """
        Create one incident per distinct alert rule. If there are 4 alerts with
        rule ID 550 and 2 alerts with rule ID 80792, only two alerts are created.
        """
        PerAlert = "per-alert"
        """
        Create one incident for every alert.

        .. warning:: Using this option is highly discouraged, as it will
                    potentially create a lot of incidents.

        .. note:: Enrichment is curently not implemented for this option.
        """
        Never = "never"
        """
        Never create incidents.

        .. note:: :octiu:`incident response cases <exploring-cases>` are still
                  created if :attr:`~Config.create_incident_response` is True.
        """

    class AlertRuleSeverity(int, Enum):
        """
        Alert rule level severity

        A convenience mapping from four severity levels to a :wazuh:`Wazuh alert rule
        level <ruleset/rules-classification.html>`.
        """

        Low = 2
        """
        Low severity
        """
        Medium = 7
        """
        Medium severity
        """
        High = 11
        """
        High severity
        """
        Critical = 14
        """
        Critical severity
        """

    enrich: EnrichmentConfig = Field(default_factory=lambda: EnrichmentConfig())
    """
    Settings for what and how to enrich
    """
    opensearch: OpenSearchConfig = Field(
        default_factory=lambda: OpenSearchConfig.model_validate({})
    )
    api: WazuhAPIConfig = Field(default_factory=lambda: WazuhAPIConfig())

    max_tlp: TLPLiteral = Field(
        title="Max TLP",
        description="Max TLP to allow for lookups",
    )
    # TODO: Allow marking definitions IDs as well:
    tlps: set[str] | None = Field(
        default="TLP:AMBER+STRICT",
    )
    """
    TLP markings to use for all created STIX entities

    The marking definitions may be specified with or without a "TLP:" prefix,
    and several definitions may be specified, separated by a comma. See
    :py:attr:`max_tlp` for possible values.
    """
    hits_abort_limit: int | None = Field(
        gt=0,
        default=1000,
    )
    """
    Number of OpenSearch matches (total matches, not returned results) that
    should cause further processing to abort. If a large number of matches are
    found, aborting prevents the connector from creating a lot of noisy
    results.
    """
    bundle_abort_limit: int | None = Field(
        gt=0,
        default=500,
    )
    """
    Number of STIX entities that should cause further processing to abort. If
    the connector produces a large number of STIX entities during enrichment,
    this setting may be used as a safe guard to prevent littering OpenCTI with
    a lot of noise.
    """
    system_name: str = Field(
        min_length=1,
        default="Wazuh SIEM",
    )
    """
    The name of the :octiu:`STIX identity (type system)
    <exploring-entities/#systems>` referenced in sightings and incidents
    """
    agents_as_systems: bool = True
    """
    Whether a :octiu:`STIX identity (type system)
    <exploring-entities/#systems>` should be created for every agent referenced
    in sightings and incidents. If set to false, :py:attr:`system_name` will be
    used instead.
    """
    search_agent_ip: bool = False
    """
    Whether to include agents' addresses when searching for IPv4/IPv6 address
    observables
    """
    search_agent_name: bool = False
    """
    Whether to search agents' names (typically, but not necessarily, hostnames)
    when searching for domain name and hostname observables
    """
    create_obs_sightings: bool = True
    """
    Create sightings of observables even if there are no indicators tied to it

    If False, sightings will only be created if the observable entity has one
    or more indicators "based on" it. The indicator pattern is not considered.
    """
    max_extrefs: int = Field(
        ge=0,
        default=10,
    )
    """
    Maximum number of external references to create per sighting

    In addition to the limit :py:attr:`max_extrefs_per_alert_rule`, this limit
    dictates how many external references to alerts in Wazuh to create in total
    per sighting. See also :py:attr:`max_extrefs_per_alert_rule`,
    :py:attr:`max_notes` and :py:attr:`max_notes_per_alert_rule`.
    """
    max_extrefs_per_alert_rule: int = Field(
        ge=0,
        default=2,
    )
    """
    Maximum number of external references to create per alert rule per sighting

    See also :py:attr:`max_extrefs`, :py:attr:`max_notes` and
    :py:attr:`max_notes_per_alert_rule`
    """
    max_notes: int = Field(
        ge=0,
        default=10,
    )
    """
    Maximum number of alert :octiu:`notes <exploring-analysis/#notes>` to
    create per sighting

    In addition to the limit :py:attr:`max_notes_per_alert_rule`, this limit
    dictates how many alert notes to create in total per sighting. See also
    :py:attr:`max_notes_per_alert_rule`, :py:attr:`max_extrefs` and
    :py:attr:`max_extrefs_per_alert_rule`.
    """
    max_notes_per_alert_rule: int = Field(
        ge=0,
        default=2,
    )
    """
    Maximum number of alert :octiu:`notes <exploring-analysis/#notes>` to
    create per sighting

    See also :py:attr:`max_notes_per_alert_rule`, :py:attr:`max_extrefs`,
    :py:attr:`max_extrefs_per_alert_rule`.
    """
    create_sighting_summary: bool = True
    """
    Whether to create a summary :octiu:`STIX note <exploring-analysis/#notes>`
    about each enrichment, along with OpenSearch query and results information,
    and attach it to all sightings. See :ref:`enrichment_note`.
    """
    create_incident_summary: bool = True
    """
    Whether to create a summary :octiu:`STIX note <exploring-analysis/#notes>`
    about each enrichment, along with OpenSearch query and results information,
    and attach it to all incidents.

    See also :py:attr:`create_sighting_summary`. See :ref:`enrichment_note`.",
    """
    require_indicator_for_incidents: bool = True
    """
    Only create incidents if the observable has indicators tied to it

    Otherwise, only sightings (depending on :py:attr:`create_obs_sightings`)
    will be created.",
    """
    create_incident: IncidentCreateMode = IncidentCreateMode.PerSighting
    """
    How and when to create incidents

    See :attr:`IncidentCreateMode`.
    """
    vulnerability_incident_cvss3_score_threshold: float | None = Field(
        ge=0, le=10, default=None
    )
    """
    Minimum vulnerability CVSS3 score needed to create incidents

    Creating incidents for every vulnerability (or several incidents, depending
    on :attr:`create_incident`) can quickly become very noisy. This setting
    ensures that incidents are only created for vulenerability sightings if a
    CVSS3 score is present in the vulnerability, and if that score is high
    enough. If this setting is None, incidents will never be created.

    Sightings will always be created, regardless of whether the CVSS3 score is
    present and above the threshold.
    """
    # TODO: low,medium,high etc too:
    create_incident_threshold: int = Field(
        ge=1,
        le=15,
        default=1,
    )
    """
    :wazuh:`Alert rule level <ruleset/rules-classification.html>` threshold for
    creating incidents

    If the alert from OpenSearch has a rule level below this value, no incident
    will be created. However, a sighting may still be created.
    :py:const:`AlertRuleSeverity` may also be used",
    """
    create_agent_ip_observable: bool = True
    """
    Whether to create an IP address observable and relate it to agent systems
    """
    create_agent_hostname_observable: bool = True
    """
    Whether to create hostname observable and relate it to agent systems
    """
    ignore_private_addrs: bool = True
    """
    Whether to ignore IP addresses in private address spaces when searching for
    IP address observables
    """
    ignore_own_entities: bool = False
    """
    Whether to ignore all entities authored by this connector (:attr:`author`)

    All entities with this author will be ignored. See FIXREF: recusion. See
    also :attr:`label_ignore_list`, which may be a better solution.
    """
    enrich_agent: bool = True
    """
    Enrich agent system identities with information from the Wazuh API (if
    enabled). The following information is provided as a Markdown table in the
    identity description:

    .. list-table:: Agent information
       :stub-columns: 1

       * - ID
         - Three-digit agent ID
       * - Name
         - (typically hostname)
       * - Status
         -   * active
             * pending
             * never_connected
             * disconnected
       * - OS name
         - e.g. Ubuntu, Microsoft Windows 10 Pro
       * - OS version
         - e.g. 20.0.4.6 LTS, 10.0.19045.4170
       * - Agent version
         - e.g. Wazuh v4.7.3
       * - IP address
         - (current public-facing IP address)
    """
    label_ignore_list: set[str] = Field(
        default={"hygiene", "wazuh_ignore"},
    )
    """
    List of lables which, if present in the entity, will make the connector to
    stop processing

    This is usful for ignoring low-quality or noisy data, and to prevent the
    connector from running on its own enriched data. See FIXREF recursion.
    """
    # TODO: Fix wazuh.py to support set:
    enrich_labels: set[str] = Field(
        default=["wazuh_ignore"],
    )
    """
    List of labels to attach to all enriched observables

    The main use case for these labels is to prevent the connector from
    automatically running on its own entities. See FIXREF recursion.
    """
    create_incident_response: bool = True
    """
    Create an :octiu:`incident response case <exploring-cases>` if there any
    incidents created

    Cases are very useful to get an overview, and is the only entity that will
    include reference to observables created through enrichment.
    """
    author_name: str = "Wazuh"
    """
    Name used for the :octiu:`STIX identity (type system)
    <exploring-entities/#systems>` that will be used as author for all created
    entities
    """
    app_url: AnyHttpUrl

    @field_validator("max_tlp", mode="before")
    @classmethod
    def normalise_tlp(cls, tlp):
        """
        Normalise TLP string to uppercase and prefixed with "TLP:"

        Examples:

        >>> Config.normalise_tlp('white')
        'TLP:WHITE'
        >>> Config.normalise_tlp('tlp:ReD')
        'TLP:RED'
        """
        return re.sub(r"^(tlp:)?", "TLP:", tlp, flags=re.IGNORECASE).upper()

    @field_validator("tlps", "label_ignore_list", mode="before")
    @classmethod
    def parse_comma_string(cls, values):
        """
        Convert a comma-separated string of TLP marking definitions into a set

        Examples:

        >>> sorted(Config.parse_comma_string('tlp:white,tlp:red'))
        ['tlp:red', 'tlp:white']
        >>> sorted(Config.parse_comma_string('label1,label2'))
        ['label1', 'label2']
        """
        return comma_string_to_set(values)

    @field_validator("tlps", mode="after")
    @classmethod
    def convert_tlp_strings(cls, tlps):
        """
        Convert each TLP string in the tlps iterable to a set of TLP marking
        definition IDs

        >>> sorted(Config.convert_tlp_strings(['white', 'green', 'white']))
        ['marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da', 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9']
        """
        return {
            tlp_id
            for tlp in tlps
            for tlp_id in (
                tlp_marking_from_string(tlp) if isinstance(tlp, str) else tlp,
            )
            if tlp_id is not None
        }

    @field_validator("tlps", mode="after")
    @classmethod
    def validate_id(cls, ids: Iterable[str]):
        """
        Ensure that the string is a STIX standard ID (<type>--<UUID>)
        """
        assert all(validate_stix_id(id) for id in ids)
        return ids

    # TODO: depend on opensearch hits:
    # @field_validator("hits_abort_limit", mode="after")
    # @classmethod
    # def hits_abort_above_max_hits(cls, abort_limit: int | None, info: ValidationInfo):
    #    """
    #    Ensure that abort_limit is not below limit
    #    """
    #    assert abort_limit is None or abort_limit >= info.data["limit"]
    #    return abort_limit

    @field_validator("max_extrefs_per_alert_rule", mode="after")
    @classmethod
    def max_ext_refs_below_total_max(cls, max: int | None, info: ValidationInfo):
        """
        Ensure that max_extrefs is not below max_extrefs_per_alert_rule
        """
        max_total = info.data["max_extrefs"]
        assert max == max_total == 0 or max <= max_total
        return max

    @field_validator("max_notes_per_alert_rule", mode="after")
    @classmethod
    def max_notes_below_total_max(cls, max: int | None, info: ValidationInfo):
        """
        Ensure that max_notes is not below max_notes_per_alert_rule
        """
        max_total = info.data["max_notes"]
        assert max == max_total == 0 or max <= max_total
        return max

    @field_validator("app_url", mode="before")
    @classmethod
    def parse_http_url(cls, url: str | AnyHttpUrl | None) -> AnyHttpUrl | None:
        """
        Convert a URL string to a AnyHttpUrl
        """
        if url is None:
            return None
        elif isinstance(url, AnyUrl):
            return url
        else:
            return AnyHttpUrl(url)

    @field_validator("app_url", mode="after")
    @classmethod
    def validate_http_url(cls, url: AnyHttpUrl) -> AnyHttpUrl:
        """
        Verify that a HTTP URL does not contain unexpected properties

        The URL must

        * Contain the schemes http or https
        * Contain a host (TLD not required)

        and must not

        * Contain a username (set in :attr:`username` instead)
        * Contain a password (set in :attr:`password` instead)
        * Contain a query or fragments
        """
        verify_url(url, throw=True)
        return url

    # TODO: move into a base class and inherit, along with model_config assignment
    @classmethod
    def from_env(cls):
        return cls.model_validate({})
