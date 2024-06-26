import re
from pydantic import (
    AnyUrl,
    AnyHttpUrl,
    Field,
    field_validator,
    ValidationInfo,
)
from pydantic_settings import SettingsConfigDict
from typing import Iterable

from .opencti_config import OpenCTIConfig
from .connector_config import ConnectorConfig
from .search_config import SearchConfig
from .opensearch_config import OpenSearchConfig
from .enrich_config import EnrichmentConfig
from .stix_helper import TLPLiteral, tlp_marking_from_string, validate_stix_id
from .utils import comma_string_to_set, verify_url
from .config_base import ConfigBase, FuzzyEnum
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
    Complete connector configuration

    Settings are grouped together in relevant objects, like :attr:`search`,
    :attr:`enrich` and :attr:`opencti`. Every setting may also be loaded from
    environment variables, where the setting name is capitalised and prefixed
    by *WAZUH\\_* or a prefixed specified by its group (WAZUH_SEARCH\\_,
    WAZUH_ENRICH\\_, OPENCTI\\_ etc.).
    """

    model_config = SettingsConfigDict(
        env_prefix="WAZUH_", validate_assignment=True, env_file=".env"
    )

    class IncidentCreateMode(FuzzyEnum):
        """
        How and when incidents should be created

        If :octiu:`incidents <exploring-events/#incidents>` should be created
        (see :ref:`require indicator <require-indicator>`), this enumerator
        determines how incidents are created.

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

    opencti: OpenCTIConfig = Field(default_factory=OpenCTIConfig.from_env)
    """
    OpenCTI-specific configuration
    """
    connector: ConnectorConfig = Field(default_factory=ConnectorConfig.from_env)
    """
    OpenCTI connector-specific configuration
    """
    search: SearchConfig = Field(default_factory=SearchConfig)
    """
    Settings for how searching should be performed
    """
    enrich: EnrichmentConfig = Field(default_factory=EnrichmentConfig)
    """
    Settings for what and how to enrich
    """
    opensearch: OpenSearchConfig = Field(
        default_factory=lambda: OpenSearchConfig.model_validate({})
    )

    max_tlp: TLPLiteral
    """
    Max :term:`TLP` to allow for lookups
    """
    # TODO: Allow marking definitions IDs as well:
    # TODO: use TLPLiteral here as well
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

    .. seealso::

        Consider adjusting :attr:`which entities to enrich
        <wazuh.enrich_config.EnrichmentConfig.types>` to lower the number of
        bundles produced through :ref:`enrichment <enrichment>`.
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
    and attach it to all sightings. See :ref:`enrichment and notes <notes>`.
    """
    create_incident_summary: bool = True
    """
    Whether to create a summary :octiu:`STIX note <exploring-analysis/#notes>`
    about each enrichment, along with OpenSearch query and results information,
    and attach it to all incidents.

    See :py:attr:`create_sighting_summary` (this is the same summary).
    """
    require_indicator_for_incidents: bool = True
    """
    Only create incidents if the observable has indicators tied to it

    Otherwise, only sightings (depending on :py:attr:`create_obs_sightings`)
    will be created.

    .. seealso::

        :ref:`Require indicator <require-indicator>` explains how several
        settings determine when to ceate incidents.
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
    :term:`CVSS3` score is present in the vulnerability, and if that score is
    high enough. If this setting is None, incidents will never be created.

    If the CVSS3 score is unavailable, but the CVSS3 severity is preent, the
    severity's corresponding score (the median) is used.

    Sightings will always be created, regardless of whether the CVSS3 score is
    present and above the threshold.
    """
    vulnerability_incident_active_only: bool = True
    """
    Only create incidents when a vulnerability is still active in a system

    If this setting is enabled, incidents will not be created for
    vulernabilities spotted in a system, if the vulnerability has since been
    removed or fixed (by patching the vulnerable software or removing it). If
    the vulnerability is active somehow again after having been fixed, an
    innident will be created.

    Note that if a search is limited due to too many hits, incidents may be
    created due to lack of information.
    """
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


    .. note:: Note that an alert rule level is not necessarily a good filter. A
       :term:`FIM`/syscheck alert informing that a file has been added to a
       system is not a high-severity alert, but it could be the alert that
       results in an :term:`IoC` match against a file hash.
    """
    # TODO: apply this as a filter in OpenSearch instead of filtering the
    # results:
    rule_exclude_list: set[str] = set()
    """
    Ignore all alerts with this :term:`rule ID <Alert rule ID>`

    .. seealso::

        If you want to keep sightings from alerts, but avoid getting incidents,
        configure :attr:`incident_rule_exclude_list` instead.
    """
    incident_rule_exclude_list: set[str] = set()
    """
    Do not create incidents for alerts with these :term:`rule IDs <Alert rule ID>`

    This setting may be useful to limit noise from alerts caused by login
    attempts and web server accceses on public-facing servers. Sightings are
    still created. Use :attr:`rule_exclude_list` instead if you want to ignore
    these alerts altogether.

    Here are some notable rules that may produce a lot of noise if your
    :term:`IoCs <IoC>` include a lot of IP addresses from spam and abuse
    sources:

    .. list-table:: Noisy :term:`alert rules <Alert rule ID>`
       :header-rows: 1

       * - Rule ID
         - Description
       * - 5503
         - PAM: User login failed
       * - 5710
         - sshd: Attempt to login using a non-existent user
       * - 5718
         - sshd: Attempt to login using a denied user
       * - 5762
         - sshd: connection reset
       * - 31101
         - Web server 400 error code
    """
    create_agent_ip_observable: bool = True
    """
    Whether to create an IP address observable and relate it to agent systems
    """
    create_agent_hostname_observable: bool = True
    """
    Whether to create hostname observable and relate it to agent systems
    """
    ignore_own_entities: bool = False
    """
    Whether to ignore all entities authored by this connector (:attr:`author`)

    All entities with this author will be ignored. See FIXREF: recusion. See
    also :attr:`label_ignore_list`, which may be a better solution.
    """
    label_ignore_list: set[str] = Field(
        default={"hygiene", "wazuh_ignore"},
    )
    """
    List of labels which, if present in the entity, will make the connector to
    stop processing

    This is usful for ignoring low-quality or noisy data, and to prevent the
    connector from running on its own enriched data (which could lead to
    "endless" recursion).

    .. seealso::

        Configure :attr:`enrich_labels` to set which labels that the connector
        should include on entities created through :ref:`enrichment <enrichment>`.
    """
    enrich_labels: set[str] = Field(
        default=["wazuh_ignore"],
    )
    """
    List of labels to attach to all enriched observables

    The main use case for these labels is to prevent the connector from
    automatically running on its own entities (which could lead to "endless"
    recursion).

    .. note::

        When modifying this setting, be sure to include relevant labels in
        :attr:`label_ignore_list`.
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
    """
    URL used to create links to the Wazuh dashboard
    """
    # TODO: include in doc everywhere that refers to create_obs_sightings and require_indicator_for_incidents
    require_indicator_detection: bool = False
    """
    Only look up indicators whose *detection* field is true

    If :attr:`create_obs_sightings` is false or if
    :attr:`require_indicator_for_incidents` is true, indicators play a role in
    how events are created. This setting ignores indicators that do not have
    the *detection* property set to true. Not all sources set this field, so it
    is disabled by default.

    In recent OpenCTI versions, :octiu:`indicator lifecycle management
    <indicators-lifecycle>` will automatically set *detection* to false
    according to :octia:`decay rules <decay-rules>`.
    """
    # TODO: include in doc everywhere that refers to create_obs_sightings and require_indicator_for_incidents
    ignore_revoked_indicators: bool = True
    """
    Only look up indicators that are not revoked

    If :attr:`create_obs_sightings` is false or if
    :attr:`require_indicator_for_incidents` is true, indicators play a role in
    how events are created. This setting ignores indicators that have the
    *revoked* property set to true.

    In recent OpenCTI versions, :octiu:`indicator lifecycle management
    <indicators-lifecycle>` will automatically set *revoked* to true
    according to :octia:`decay rules <decay-rules>`.
    """
    indicator_score_threshold: int | None = Field(ge=0, le=100, default=None)
    """
    Only look up indicators whose score is above or equals this threshold

    If :attr:`create_obs_sightings` is false or if
    :attr:`require_indicator_for_incidents` is true, indicators play a role in
    how events are created. This setting ignores indicators that have the
    *revoked* property set to true.

    In recent OpenCTI versions, :octiu:`indicator lifecycle management
    <indicators-lifecycle>` will automatically adjust the score according to
    :octia:`decay rules <decay-rules>`.
    """

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
        if not all(validate_stix_id(id) for id in ids):
            raise ValueError(f"STIX ID list contains an invalid ID: {ids}")

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
    def max_ext_refs_below_total_max(
        cls, max_per_rule: int | None, info: ValidationInfo
    ):
        """
        Ensure that max_extrefs is not below max_extrefs_per_alert_rule
        """
        if max_per_rule > info.data["max_extrefs"]:
            raise ValueError(
                "max_extrefs_per_alert_rule must be less or equal to max_extrefs"
            )

        return max_per_rule

    @field_validator("max_notes_per_alert_rule", mode="after")
    @classmethod
    def max_notes_below_total_max(cls, max_per_rule: int | None, info: ValidationInfo):
        """
        Ensure that max_notes is not below max_notes_per_alert_rule
        """
        if max_per_rule > info.data["max_notes"]:
            raise ValueError(
                "max_notes_per_alert_rule must be less or equal to max_notes"
            )

        return max_per_rule

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
