import re
import dateparser
import json
from datetime import datetime
from pydantic import (
    Field,
    field_validator,
    ValidationInfo,
)
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Any, Iterable, TypeVar
from .stix_helper import TLPLiteral, tlp_marking_from_string, validate_stix_id
from .utils import comma_string_to_set
from enum import Enum

T = TypeVar("T")


class EnrichmentConfig(BaseSettings):
    """
    This configuration dictates how the connector should enrich incidents with
    observables and other entities
    """

    model_config = SettingsConfigDict(
        env_prefix="WAZUH_ENRICH_", validate_assignment=True
    )

    class EntityType(Enum):
        """
        Entity types to enrich

        See :doc:`enrichment` for details.
        """

        Account = "user-account"
        """
        Enrich :stix:`user accounts <#_azo70vgj1vm2>`

        User accounts are enriched from FIXME.
        """
        AttackPattern = "attack-pattern"
        """
        Enrich :stix:`attack patterns <#_axjijf603msy>` (MITRE)

        Create and reference MITRE TTPs from rule.mitre.id. Only the MITRE ID is
        used, so unless another connector like :ghconnector:`mitre
        <external-import/mitre>` is used, the attack patterns created by
        opencti-wazuh will be empty, containing only the MITRE ID.
        """
        Directory = "directory"
        """
        Enrich :stix:`directories <#_lyvpga5hlw52>` from

            * data.audit.directory.name
            * data.home
            * data.osquery.columns.directory
            * data.pwd

        The following properties are set:

            * path
        """
        Domain = "domain-name"
        """
        Enrich :stix:`domain names <#_prhhksbxbg87>` from

            * data.dns.question.name
            * data.office365.ParticipantInfo.ParticipatingDomains
            * data.osquery.columns.hostname
            * data.win.eventdata.queryName
            * data.win.system.computer

        The following properties are set:

            * value
        """
        EMailAddr = "email-addr"
        """
        Enrich :stix:`e-mail addresses <#_wmenahkvqmgj>` from

            * data.gcp.protoPayload.authenticationInfo.principalEmail
            * data.office365.UserId

        The following properties are set:

            * value
        """
        File = "file"
        """
        Enrich :stix:`files <#_99bl2dibcztv>`. File names (name and
        x_opencti_additional_names) are fetched from

            * data.ChildPath
            * data.ParentPath
            * data.Path
            * data.TargetFilename
            * data.TargetPath
            * data.audit.file.name
            * data.audit.file.name
            * data.file
            * data.sca.check.file
            * data.smbd.filename
            * data.smbd.new_filename
            * data.virustotal.source.file
            * data.win.eventdata.file
            * data.win.eventdata.filePath

        Hashes (MD5, SHA-1, and SHA-256) are fetched from

            * data.osquery.columns.md5
            * data.osquery.columns.sha1
            * data.osquery.columns.sha256
            * syscheck.md5_after
            * syscheck.sha1_after
            * syscheck.sha256_after

        If FIXME:filename_behaviour is FIXME, a nested Directory observable
        will also be created and set as *parent directory*. If FIXME is FIXME,
        the filename will contain only the filename, otherwise the full path
        will be used as filename. This also applies to all filenames in
        x_opencti_additional_names.

        FIXME: size and othes
        """
        IPv4Address = "ipv4-addr"
        IPv6Address = "ipv6-addr"
        MAC = "max-addr"
        NetworkTraffic = "network-traffic"
        Process = "process"
        RegistryKey = "windows-registry-key"
        Tool = "tool"
        URL = "url"
        UserAgent = "user-agent"

    types: set[EntityType] = Field(title="Enrichment types", default=set())
    """
    Which entity types to enrich
    """

    @field_validator("types", mode="before")
    @classmethod
    def parse_comma_string(cls, types):
        """
        Convert a comma-separated string of types to a set

        Examples:

        >>> sorted(EnrichmentConfig.parse_comma_string('process,file'))
        ['file', 'process']
        >>> EnrichmentConfig.parse_comma_string('all') == set(EnrichmentConfig.EntityType)
        True
        """
        return comma_string_to_set(types, cls.EntityType)


# TODO: add aliases to create sensible env names
# TODO: Use autodoc_pydantic_field_doc_policy=docstring and move and improve
# format of description into docstrings
# TODO: Move settings into groups (opensearch, wazuh_api, enrich etc.…)
class Config(BaseSettings):
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

    enrich: EnrichmentConfig = EnrichmentConfig()
    """
    Settings for what and how to enrich
    """
    max_tlp: TLPLiteral = Field(
        title="Max TLP",
        description="Max TLP to allow for lookups",
    )
    # TODO: Allow marking definitions IDs as well:
    tlps: set[str] | None = Field(
        title="TLP IDs",
        description='TLP markings to use for all created STIX entities. The marking definitions may be specified with or without a "TLP:" prefix, and several definitions may be specified, separated by a comma. See :py:attr:`max_tlp` for possible values.',
        default="TLP:AMBER+STRICT",
    )
    hits_limit: int = Field(
        title="Maximum number of hits",
        description="Maximum number of results to return from the OpenSearch alert query (after ordering by timestamp (and rule.level if :py:attr:`order_by_rule_level` is True)).",
        gt=0,
        # TODO: sensible max limit
        default=10,
    )
    hits_abort_limit: int | None = Field(
        title="Hits abort limit",
        description="Number of OpenSearch matches (total matches, not returned results) that should cause further processing to abort. If a large number of matches are found, aborting prevents the connector from creating a lot of noisy results.",
        gt=0,
        default=1000,
    )
    bundle_abort_limit: int | None = Field(
        title="STIX bundle entities abort limit",
        description="Number of STIX entities that should cause further processing to abort. If the connector produces a large number of STIX entities during enrichment, this setting may be used as a safe guard to prevent littering OpenCTI with a lot of noise",
        gt=0,
        default=500,
    )
    system_name: str = Field(
        title="System name",
        description="The name of the :octiu:`STIX identity (type system) <exploring-entities/#systems>` referenced in sightings and incidents",
        min_length=1,
        default="Wazuh SIEM",
    )
    agents_as_systems: bool = Field(
        title="Agents as systems",
        description="Whether a :octiu:`STIX identity (type system) <exploring-entities/#systems>` should be created for every agent referenced in sightings and incidents. If set to false, :py:attr:`system_name` will be used instead.",
        default=True,
    )
    search_agent_ip: bool = Field(
        title="Search agent IPs",
        description="Whether to include agents' addresses when searching for IPv4/IPv6 address observables",
        default=False,
    )
    search_agent_name: bool = Field(
        title="Search agent names",
        description="Whether to search agents' names (typically, but not necessarily, hostnames) when searching for domain name and hostname observables",
        default=False,
    )
    search_after: datetime | None = Field(
        title="Search after",
        description='Search for alerts in OpenSearch after this point in time, which may be specified either as a timestamp or a relative time (like "2 months ago")',
        default=None,
    )
    search_include: str | None = Field(
        title="Search include",
        description='Search query to include in all OpenSearch alert searches. It may either be a DSL json object, or alternatively a comma-separated string with key=value items that will be transformed into a number of full-text "match" query. In both cases, the query will be added to a "bool" "must" array.',
        default=None,
    )
    search_exclude: str | None = Field(
        title="Search exclude",
        description='Search query to include in all OpenSearch alert searches to exclude results. It may either be a DSL json object, or alternatively a comma-separated string with key=value items that will be transformed into a number of full-text "match" query. In both cases, the query will be added to a "bool" "must_not" array. The default value will exclude alerts produced by the `wazuh-opencti <https://github.com/misje/wazuh-opencti>`_ Wazuh integration.',
        default="data.integration=opencti",
    )
    create_obs_sightings: bool = Field(
        title="Create observable sightings",
        description='Create sightings of observables even if there are no indicators tied to it. If False, sightings will only be created if the observable entity has one or more indicators "based on" it. The indicator pattern is not considered.',
        default=True,
    )
    max_extrefs: int = Field(
        title="Maximum external references",
        description="Maximum number of external references to create per sighting. In addition to the limit :py:attr:`max_extrefs_per_alert_rule`, this limit dictates how many external references to alerts in Wazuh to create in total per sighting. See also :py:attr:`max_extrefs_per_alert_rule`, :py:attr:`max_notes` and :py:attr:`max_notes_per_alert_rule`.",
        ge=0,
        default=10,
    )
    max_extrefs_per_alert_rule: int = Field(
        title="Maximum external references per alert rule",
        description="Maximum number of external references to create per alert rule per sighting. See also :py:attr:`max_extrefs`, :py:attr:`max_notes` and :py:attr:`max_notes_per_alert_rule`",
        ge=0,
        default=2,
    )
    max_notes: int = Field(
        title="Maximum notes",
        description="Maximum number of alert :octiu:`notes <exploring-analysis/#notes>` to create per sighting. In addition to the limit :py:attr:`max_notes_per_alert_rule`, this limit dictates how many alert notes to create in total per sighting. See also :py:attr:`max_notes_per_alert_rule`, :py:attr:`max_extrefs` and :py:attr:`max_extrefs_per_alert_rule`.",
        ge=0,
        default=10,
    )
    max_notes_per_alert_rule: int = Field(
        title="Maximum notes per alert rule",
        description="Maximum number of alert :octiu:`notes <exploring-analysis/#notes>` to create per sighting. See also :py:attr:`max_notes_per_alert_rule`, :py:attr:`max_extrefs`, :py:attr:`max_extrefs_per_alert_rule`.",
        ge=0,
        default=2,
    )
    create_sighting_summary: bool = Field(
        title="Create sighting summary",
        description="Whether to create a summary :octiu:`STIX note <exploring-analysis/#notes>` about each enrichment, along with OpenSearch query and results information, and attach it to all sightings. See :ref:`enrichment_note`.",
        default=True,
    )
    create_incident_summary: bool = Field(
        title="Create incident summary",
        description="Whether to create a summary :octiu:`STIX note <exploring-analysis/#notes>` about each enrichment, along with OpenSearch query and results information, and attach it to all incidents. See also :py:attr:`create_sighting_summary`. See :ref:`enrichment_note`.",
        default=True,
    )
    require_indicator_for_incidents: bool = Field(
        title="Require indicator for incidents",
        description="Only create incidents if the observable has indicators tied to it. Otherwise, only sightings (depending on :py:attr:`create_obs_sightings`) will be created.",
        default=True,
    )
    create_incident: IncidentCreateMode = Field(
        title="Incident create mode",
        description="How and when to create incidents. See :attr:`IncidentCreateMode`.",
        default=IncidentCreateMode.PerSighting,
    )
    create_incident_threshold: int = Field(
        title="Incident creation threshold",
        description=":wazuh:`Alert rule level <ruleset/rules-classification.html>` threshold for creating incidents. If the alert from OpenSearch has a rule level below this value, no incident will be created. However, a sighting may still be created. :py:const:`AlertRuleSeverity` may also be used",
        ge=1,
        le=15,
        default=1,
    )
    create_agent_ip_obs: bool = Field(
        title="Create agent IP observable",
        description="Whether to create an IP address observable and relate it to agent systems",
        default=False,
    )
    create_agent_host_obs: bool = Field(
        title="Create agent hostname observable",
        description="Whether to create hostname observable and relate it to agent systems",
        default=False,
    )
    ignore_private_addrs: bool = Field(
        title="Ignore private addresses",
        description="Whether to ignore IP addresses in private address spaces when searching for IP address observables",
        default=True,
    )
    ignore_own_entities: bool = Field(
        title="Ignore own entities",
        description="Whether to ignore all entities authored by this connector (:attr:`authro`). All entities with this author will be ignored. See FIXREF: recusion. See also :attr:`label_ignore_list`, which may be a better solution.",
        default=False,
    )
    order_by_rule_level: bool = Field(
        title="Order by rule level",
        description="Order OpenSearch alert results by :wazuh:`alert rule level <ruleset/rules-classification.html>` (asc.), then implicitly by timestamp (desc.) before returning :py:attr:`hits_limit` number of results",
        default=False,
    )
    enrich_agent: bool = Field(
        title="Enrich agents",
        default=True,
    )
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
        title="Label ignore list",
        description="List of lables which, if present in the entity, will make the connector to stop processing. This is usful for ignoring low-quality or noisy data, and to prevent the connector from running on its own enriched data. See FIXREF recursion.",
        default={"hygiene", "wazuh_ignore"},
    )
    # TODO: Fix wazuh.py to support set:
    enrich_labels: list[str] = Field(
        title="Enrich labels",
        description="List of labels to attach to all enriched observables. The main use case for these labels is to prevent the connector from automatically running on its own entities. See FIXREF recursion.",
        default=["wazuh_ignore"],
    )
    create_incident_response: bool = Field(
        title="Create incident response",
        description="Create an :octiu:`incident response case <exploring-cases>` if there any incidents created. Cases are very useful to get an overview, and is the only entity that will include reference to observables created through enrichment.",
        default=True,
    )
    author_name: str = Field(
        title="Author name",
        description="Name used for the :octiu:`STIX identity (type system) <exploring-entities/#systems>` that will be used as author for all created entities",
        default="Wazuh",
    )

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
    def parse_comma_string(cls, tlps):
        """
        Convert a comma-separated string of TLP marking definitions into a set

        Examples:

        >>> sorted(Config.parse_comma_string('tlp:white,tlp:red'))
        ['tlp:red', 'tlp:white']
        >>> sorted(Config.parse_comma_string('label1,label2'))
        ['label1', 'label2']
        """
        return comma_string_to_set(tlps)

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

    @field_validator("hits_abort_limit", mode="after")
    @classmethod
    def hits_abort_above_max_hits(cls, abort_limit: int | None, info: ValidationInfo):
        """
        Ensure that abort_limit is not below hits_limit
        """
        assert abort_limit is None or abort_limit >= info.data["hits_limit"]
        return abort_limit

    @field_validator("search_after", mode="before")
    @classmethod
    def parse_lax_datetime(
        cls, timestamp_str: datetime | str | None
    ) -> datetime | None:
        """
        Parse a timestamp-like string, either in an absolute or relative format

        Examples:

        >>> Config.parse_lax_datetime(None)
        >>> Config.parse_lax_datetime('2021-02-03')
        datetime.datetime(2021, 2, 3, 0, 0)

        TODO: test for relative times
        """
        if timestamp_str is None:
            return None
        if isinstance(timestamp_str, datetime):
            return timestamp_str

        if timestamp := dateparser.parse(timestamp_str):
            return timestamp
        else:
            raise ValueError("timestamp is invalid")

    @field_validator("search_include", "search_exclude", mode="after")
    @classmethod
    def parse_match_patterns(cls, patterns_str: str | None) -> list | None:
        """
        Parse a string with comma-separated key–value pairs in a list of
        OpenSearch DSL match query JSON objects

        If the string is a valid JSON array, it is passed on and assumed to be
        valid DSL.

        Examples:

        >>> Config.parse_match_patterns("foo=bar,baz=qux")
        [{'match': {'foo': 'bar'}}, {'match': {'baz': 'qux'}}]
        """
        if patterns_str is None:
            return None

        # Do not obther at all to try to validate DSL. If it is valid JSON,
        # just let the opensearch module attempt to use it:
        try:
            dsl = json.loads(patterns_str)
            if isinstance(dsl, list):
                return dsl
        except json.JSONDecodeError:
            pass

        # Otherwise, ensure that the string contains a list of key–value pairs
        pairs = [pattern.split("=") for pattern in patterns_str.split(",")]
        if any(len(pair) != 2 for pair in pairs):
            raise ValueError(f'The search patterns string "{patterns_str}" is invalid')

        return [{"match": {pair[0]: pair[1]}} for pair in pairs]

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
