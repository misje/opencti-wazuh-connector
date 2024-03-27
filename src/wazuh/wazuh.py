import json
import stix2
import yaml
import dateparser
import re
import ipaddress
from .opensearch import OpenSearchClient
from .wazuh_api import WazuhAPIClient
from pathlib import Path
from pycti import (
    CaseIncident,
    CustomObjectCaseIncident,
    CustomObservableHostname,
    Identity,
    Incident,
    Note,
    OpenCTIConnectorHelper,
    OpenCTIMetricHandler,
    StixCoreRelationship,
    StixSightingRelationship,
    get_config_variable,
)
from typing import Any, Final
from datetime import datetime
from urllib.parse import urljoin
from functools import reduce
from .utils import (
    has,
    rule_level_to_severity,
    priority_from_severity,
    max_severity,
    common_prefix_string,
    search_in_object_multi,
)
from .stix_helper import (
    # SCO,
    # SDO,
    # SRO,
    # StandardID,
    DUMMY_INDICATOR_ID,
    tlp_marking_from_string,
    tlp_allowed,
    # add_incidents_to_note_refs,
    entity_values,
    entity_name_value,
    incident_entity_relation_type,
    StixHelper,
)
from .sightings import SightingsCollector
from .search import AlertSearcher
from .enrich import Enricher

# TODO: Enrichment connector that uses snipeit to get system owner
# TODO: Replace ValueError with a better named exception if it is no longer a value error
# TODO: inconsistent use of _ in func. names. Fix when cleaning up, modularise and move utils into utils, stix into stix(?) modules
# TODO: update wazuh api completely in background
# FIXME: Ignoring obs. from Wazuh is not a good solution. Manual enrichment must be allowed, if so.
# TODO: escape_md() function (for use in all text going into opencti)
# TODO: Add search options to prevent too many hits, like: search_{file::name}. Hæ?
# TODO: Use TypeAlias (from typing) for things like Bundle, SCO etc.
# TODO: create helper function for creating stix objects, like stix2.Relationship that needs several references to the same variable. Add in a module that can be initied with common_args?
# TODO: create issue for getting type of enrichment (manual or automatic)
# TODO: Alert notes in incidents (already in sighting and case, but not incident)
# TODO: aws, google and office
# - user accounts
# - emails
# - files
# - directories
# FIXME: 188.95.241.209 creates missing ref to what I assume is wazu siem system
# TODO: Identities for AWS, GitHub, Office365, etc.(?)

# Notes:
# - get_config_variable with required doesn't throw if not set. Resolved by
#   using Field in the future
# - Using automation, observables can be created from indicator
# - for config, consider using pydanic and BaseSettings. Look at
# https://github.com/OpenCTI-Platform/connectors/blob/abf07fb6bd423c104a10207626520c2836d7e586/internal-enrichment/shodan-internetdb/src/shodan_internetdb/config.py#L26.
# If not, ensure empty values in required throws
# - Experiment with custom STIX patterns, like [syscheck.path:value = …] to
# create opensearch queries? Look into qualifiers in the STIX standard


# UUID_RE = r"^a[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$"
# STIX_ID_REGEX = re.compile(f".+--{UUID_RE}", re.IGNORECASE)


def parse_config_datetime(value, setting_name):
    if value is None:
        return None

    timestamp = dateparser.parse(value)
    if not timestamp:
        raise ValueError(
            f'The config variable "{setting_name}" datetime expression cannot be parsed: "{value}"'
        )

    return timestamp


# TODO: move into opensearch:
def parse_match_patterns(patterns: str):
    """
    Parse a string like "foo=bar,baz=qux" into
    [{"match": {"foo": "bar"}}, {"match": {"baz": "qux"}}]

    Parameters
    ----------
    patterns : str
               String of key=value pairs separated by comma
    """
    if patterns is None:
        return None

    pairs = [pattern.split("=") for pattern in patterns.split(",")]
    if any(len(pair) != 2 for pair in pairs):
        raise ValueError(f'The match patterns "{patterns}" is invalid')

    return [{"match": {pair[0]: pair[1]}} for pair in pairs]


def parse_incident_create_threshold(threshold: str | int | None) -> int:
    match threshold:
        case "low":
            return 2
        case "medium":
            return 7
        case "high":
            return 11
        case "critical":
            return 14
        case threshold if (
            isinstance(threshold, int)
            or (isinstance(threshold, str) and threshold.isdigit())
        ) and int(threshold) in range(1, 15):
            return int(threshold)
        case None:
            return 1
        case _:
            raise ValueError(f"WAZUH_INCIDENT_CREATE_THRESHOLD is invalid: {threshold}")


def alert_md_table(alert: dict, additional_rows: list[tuple[str, str]] = []):
    """
    Create a markdown table with key Wazuh alert information

    Any additional rows can be appended to the table using additional_rows.
    """
    s = alert["_source"]
    return (
        "|Key|Value|\n"
        "|---|-----|\n"
        f"|Rule ID|{s['rule']['id']}|\n"
        f"|Rule desc.|{s['rule']['description']}|\n"
        f"|Rule level|{s['rule']['level']}|\n"
        f"|Alert ID|{alert['_id']}/{s['id']}|\n"
    ) + "".join(f"|{key}|{value}|\n" for key, value in additional_rows)


def api_searchable_entity_type(entity_type: str):
    match entity_type:
        # case "IPv4-Addr" | "IPv6-Addr":
        # case "Network-Traffic":
        # case "Process":
        case "Software":
            return True
        case _:
            return False


class WazuhConnector:
    class MetricHelper:
        def __init__(self, metric: OpenCTIMetricHandler):
            self.metric = metric

        def __enter__(self):
            self.metric.inc("run_count")
            self.metric.state("running")
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self.metric.state("idle")
            if exc_type is not None:
                self.metric.inc("client_error_count")

    def __init__(self):
        self.CONNECTOR_VERSION: Final[str] = "0.0.1"
        # it appears that the dummy indicator has to exist for external references to work (probably not – random and inconsistent):

        config_file_path = Path(__file__).parent.parent.resolve() / "config.yml"
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.SafeLoader)
            if config_file_path.is_file()
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config, True)
        self.confidence = (
            int(self.helper.connect_confidence_level)
            if isinstance(self.helper.connect_confidence_level, int)
            else None
        )
        self.max_tlp = (
            re.sub(r"^(tlp:)?", "TLP:", tlp, flags=re.IGNORECASE).upper()
            if isinstance(
                tlp := get_config_variable(
                    "WAZUH_MAX_TLP", ["wazuh", "max_tlp"], config, required=True
                ),
                str,
            )
            else None
        )
        self.tlps = (
            [tlp]
            if (
                tlp := tlp_marking_from_string(
                    get_config_variable(
                        "WAZUH_TLP",
                        ["wazuh", "tlp"],
                        config,
                        required=True,  # type: ignore
                    )
                )
            )
            is not None
            else []
        )
        self.hits_limit = get_config_variable(
            "WAZUH_MAX_HITS", ["wazuh", "max_hits"], config, isNumber=True, default=10
        )
        self.hits_abort_limit = (
            limit
            if isinstance(
                limit := get_config_variable(
                    "WAZUH_MAX_HITS_ABORT",
                    ["wazuh", "max_hits_abort"],
                    config,
                    isNumber=True,
                    # default=1000,
                ),
                int,
            )
            else None
        )
        self.bundle_abort_limit = (
            limit
            if isinstance(
                limit := get_config_variable(
                    "WAZUH_MAX_BUNDLES_ABORT",
                    ["wazuh", "max_bundles_abort"],
                    config,
                    isNumber=True,
                    # default=200,
                ),
                int,
            )
            else None
        )
        self.system_name = get_config_variable(
            "WAZUH_SYSTEM_NAME", ["wazuh", "system_name"], config, default="Wazuh SIEM"
        )
        self.agents_as_systems = get_config_variable(
            "WAZUH_AGENTS_AS_SYSTEMS",
            ["wazuh", "agents_as_systems"],
            config,
            default=True,
        )
        self.alerts_as_notes = get_config_variable(
            "WAZUH_ALERTS_AS_NOTES",
            ["wazuh", "alerts_as_notes"],
            config,
            default=True,
        )
        self.search_agent_ip = get_config_variable(
            "WAZUH_SEARCH_AGENT_IP",
            ["wazuh", "search_agent_ip"],
            config,
            default=False,
        )
        self.search_agent_name = get_config_variable(
            "WAZUH_SEARCH_AGENT_NAME",
            ["wazuh", "search_agent_name"],
            config,
            default=False,
        )
        self.search_after = parse_config_datetime(
            value=get_config_variable(
                "WAZUH_SEARCH_ONLY_AFTER", ["wazuh", "search_only_after"], config
            ),
            setting_name="search_only_after",
        )
        self.search_include = get_config_variable(
            "WAZUH_SEARCH_INCLUDE_MATCH", ["wazuh", "search_include_match"], config
        )
        self.search_exclude = get_config_variable(
            "WAZUH_SEARCH_EXCLUDE_MATCH",
            ["wazuh", "search_exclude_match"],
            config,
            default="data.integration=opencti",
        )
        self.create_obs_sightings = get_config_variable(
            "WAZUH_CREATE_OBSERVABLE_SIGHTINGS",
            ["wazuh", "create_observable_sightings"],
            config,
            default=True,
        )
        self.max_extrefs = (
            maxrefs
            if isinstance(
                maxrefs := get_config_variable(
                    "WAZUH_SIGHTING_MAX_EXTREFS",
                    ["wazuh", "sighting_max_extrefs"],
                    config,
                    isNumber=True,
                    default=10,
                ),
                int,
            )
            else 10
        )
        self.max_extrefs_per_alert_rule = (
            maxrefs
            if isinstance(
                maxrefs := get_config_variable(
                    "WAZUH_SIGHTING_MAX_EXTREFS_PER_ALERT_RULE",
                    ["wazuh", "sighting_max_extrefs_per_alert_rule"],
                    config,
                    isNumber=True,
                    default=1,
                ),
                int,
            )
            else 1
        )
        self.max_notes = (
            maxrefs
            if isinstance(
                maxrefs := get_config_variable(
                    "WAZUH_SIGHTING_MAX_NOTES",
                    ["wazuh", "sighting_max_notes"],
                    config,
                    isNumber=True,
                    default=10,
                ),
                int,
            )
            else 10
        )
        self.max_notes_per_alert_rule = (
            maxrefs
            if isinstance(
                maxrefs := get_config_variable(
                    "WAZUH_SIGHTING_MAX_NOTES_PER_ALERT_RULE",
                    ["wazuh", "sighting_max_notes_per_alert_rule"],
                    config,
                    isNumber=True,
                    default=1,
                ),
                int,
            )
            else 1
        )
        self.create_sighting_summary = get_config_variable(
            "WAZUH_SIGHTING_CREATE_SUMMARY_NOTE",
            ["wazuh", "sighting_summary_note"],
            config,
            default=True,
        )
        self.create_incident_summary = get_config_variable(
            "WAZUH_INCIDENT_CREATE_SUMMARY_NOTE",
            ["wazuh", "incident_create_summary_note"],
            config,
            default=True,
        )
        self.require_indicator_for_incidents = get_config_variable(
            "WAZUH_INCIDENT_REQUIRE_INDICATOR",
            ["wazuh", "incident_require_indicator"],
            config,
            default=True,
        )
        # TODO: verify modes using Field:
        self.create_incident = get_config_variable(
            "WAZUH_INCIDENT_CREATE_MODE",
            ["wazuh", "incident_create_mode"],
            config,
            default="per_sighting",
        )
        self.create_incident_threshold = parse_incident_create_threshold(
            get_config_variable(
                "WAZUH_INCIDENT_CREATE_THRESHOLD",
                ["wazuh", "incident_create_threshold"],
                config,
            )
        )
        self.create_agent_ip_obs = get_config_variable(
            "WAZUH_CREATE_AGENT_IP_OBSERVABLE",
            ["wazuh", "create_agent_ip_observable"],
            config,
            default=False,
        )
        self.create_agent_host_obs = get_config_variable(
            "WAZUH_CREATE_AGENT_HOSTNAME_OBSERVABLE",
            ["wazuh", "create_agent_hostname_observable"],
            config,
            default=False,
        )
        self.ignore_private_addrs = get_config_variable(
            "WAZUH_IGNORE_PRIVATE_IP_ADDRS",
            ["wazuh", "ignore_private_ip_addrs"],
            config,
            default=False,
        )
        self.ignore_own_entities = get_config_variable(
            "WAZUH_IGNORE_OWN_ENTITIES",
            ["wazuh", "ignore_own_entities"],
            config,
            default=True,
        )
        self.order_by_rule_level = get_config_variable(
            "WAZUH_ORDER_BY_RULE_LEVEL",
            ["wazuh", "order_by_rule_level"],
            config,
            default=False,
        )
        self.enrich_agent = get_config_variable(
            "WAZUH_ENRICH_AGENT", ["wazuh", "enrich_agent"], config, default=True
        )
        self.label_ignore_list = get_config_variable(
            "WAZUH_LABEL_IGNORE_LIST",
            ["wazuh", "label_ignore_list"],
            config,
            default="hygiene,wazuh",
        ).split(",")  # type: ignore
        self.enrich_labels = get_config_variable(
            "WAZUH_ENRICH_LABEL_ADD_LIST",
            ["wazuh", "enrich_label_add_list"],
            config,
            default="wazuh",
        ).split(",")  # type: ignore
        self.create_incident_response = get_config_variable(
            "WAZUH_CREATE_INCIDENT_RESPONSE",
            ["wazuh", "create_incident_response"],
            config,
            default=False,
        )

        self.stix_common_attrs = {
            "object_marking_refs": self.tlps,
            "confidence": self.confidence,
        }
        # Add moe useful meta to author?
        self.author = stix2.Identity(
            id=Identity.generate_id("Wazuh", "system"),
            **self.stix_common_attrs,
            name=get_config_variable(
                "WAZUH_AUTHOR_NAME",
                ["wazuh", "author_name"],
                config,
                default="Wazuh",
            ),
            identity_class="organization",
            description="Wazuh",
        )
        self.stix_common_attrs["created_by_ref"] = self.author["id"]
        self.stix = StixHelper(
            common_properties=self.stix_common_attrs, sco_labels=self.enrich_labels
        )
        self.enricher = Enricher(
            helper=self.helper,
            stix=self.stix,
            types=get_config_variable(
                "WAZUH_ENRICH_TYPES",
                ["wazuh", "enrich_types"],
                config,
                default=set("attack-pattern"),
            ),  # type: ignore
        )
        self.siem_system = stix2.Identity(
            id=Identity.generate_id(self.system_name, "system"),
            **self.stix_common_attrs,
            name=self.system_name,
            identity_class="system",
        )
        self.app_url = get_config_variable(
            "WAZUH_APP_URL", ["wazuh", "app_url"], config, required=True
        )
        self.alert_searcher = AlertSearcher(
            helper=self.helper,
            opensearch=OpenSearchClient(
                helper=self.helper,
                url=get_config_variable(  # type: ignore
                    "WAZUH_OPENSEARCH_URL",
                    ["wazuh", "opensearch", "url"],
                    config,
                    required=True,
                ),
                username=get_config_variable(  # type: ignore
                    "WAZUH_OPENSEARCH_USERNAME",
                    ["wazuh", "opensearch", "username"],
                    config,
                    required=True,
                ),
                password=get_config_variable(  # type: ignore
                    "WAZUH_OPENSEARCH_PASSWORD",
                    ["wazuh", "opensearch", "password"],
                    config,
                    required=True,
                ),
                limit=self.hits_limit if isinstance(self.hits_limit, int) else 10,
                index=get_config_variable(  # type: ignore
                    "WAZUH_OPENSEARCH_INDEX",
                    ["wazuh", "opensearch", "index"],
                    config,
                    default="wazuh-alerts-*",
                ),
                search_after=self.search_after,
                include_match=parse_match_patterns(self.search_include),  # type: ignore
                exclude_match=parse_match_patterns(self.search_exclude),  # type: ignore
                order_by=[{"rule.level": "desc"}] if self.order_by_rule_level else [],
                # TODO: Use Field to validate. Document that search_after is prepended if defined:
                # filters=[{"range": {"rule.level": {"gte": 8}}}],
                # filters=get_config_variable("WAZUH_SEARCH_FILTER", ["wazuh", "search_filter"], config),
            ),
            ignore_private_addrs=self.ignore_private_addrs,
            search_agent_ip=self.search_agent_ip,
            search_agent_name=self.search_agent_name,
        )
        if get_config_variable(
            "WAZUH_API_USE", ["wazuh", "api", "use"], config, default=False
        ):
            self.wazuh = WazuhAPIClient(
                helper=self.helper,
                url=get_config_variable(  # type: ignore
                    "WAZUH_API_URL", ["wazuh", "api", "url"], config, required=True
                ),
                username=get_config_variable(  # type: ignore
                    "WAZUH_API_USERNAME",
                    ["wazuh", "api", "username"],
                    config,
                    required=True,
                ),
                password=get_config_variable(  # type: ignore
                    "WAZUH_API_PASSWORD",
                    ["wazuh", "api", "password"],
                    config,
                    required=True,
                ),
                cache_filename="/var/cache/wazuh/state.json",
            )
        else:
            self.wazuh = None

    def start(self):
        if self.wazuh:
            self.wazuh.load_cache()
            self.wazuh.query_packages()
            self.wazuh.save_cache()

        self.enricher.fetch_tools()
        self.helper.metric.state("idle")
        self.helper.listen(self.process_message)

    def process_message(self, data):
        # Use a helper class that ensures to always updates the running state of the connector, as well as incrementing the error count on uncaught exceptions:
        with self.MetricHelper(self.helper.metric):
            return self._process_message(data)

    def _process_message(self, data):
        entity = None
        entity_type = "observable"
        if data["entity_id"].startswith("vulnerability--"):
            entity = self.helper.api.vulnerability.read(id=data["entity_id"])
            entity_type = "vulnerability"
        # Support looking up observables based on indicatorss:
        elif data["entity_id"].startswith("indicator--"):
            ind = self.helper.api.indicator.read(id=data["entity_id"])
            ind_obs = ind["observables"] if ind and "observables" in ind else []
            # TODO: In some distant feature, with a STIX shifter implementation
            # for Wazuh, look up the STIX pattern in the indicator and use that
            # in a search.
            if not ind_obs:
                raise ValueError("Indicator is not based on any observables")
            elif (count := len(ind_obs)) > 1:
                self.helper.connector_logger.warning(
                    f"Indicator is based on several observables; using the first out of {count}"
                )
            entity = self.helper.api.stix_cyber_observable.read(id=ind_obs[0]["id"])
        else:
            entity = self.helper.api.stix_cyber_observable.read(id=data["entity_id"])

        if entity is None:
            raise ValueError("Entity/observable not found")

        # Remove:
        self.helper.log_debug(f"ENTITY: {entity}")

        if not tlp_allowed(entity, self.max_tlp):  # type: ignore
            self.helper.connector_logger.info(f"max tlp: {self.max_tlp}")
            raise ValueError("Entity ignored because TLP not allowed")

        if (
            self.ignore_own_entities
            and has(entity, ["createdBy", "standard_id"])
            and entity["createdBy"]["standard_id"] == self.author.id
        ):
            # TODO: How to allow manual enrichments? Any way to separate automatic enrichments from manual?
            return f"Ignoring entity because it was created by {self.author.name}"

        # Figure out exactly what this does (change id format?);
        enrichment = self.helper.get_data_from_enrichment(
            data, entity["standard_id"], entity
        )
        stix_entity = enrichment["stix_entity"]
        # Remove:
        self.helper.log_debug(f"STIX_ENTITY: {stix_entity}")

        # Remove:
        if entity["entity_type"] != stix_entity["x_opencti_type"]:
            self.helper.log_debug(
                f'DIFFERENT: entity_type: {entity["entity_type"]}, x_opencti_type: {stix_entity["x_opencti_type"]}'
            )

        obs_indicators = self.entity_indicators(entity)
        # Remove:
        self.helper.log_debug(f"INDS: {obs_indicators}")

        if self.label_ignore_list and "x_opencti_labels" in stix_entity:
            matching_labels = [
                label
                for label in self.label_ignore_list
                if label in stix_entity["x_opencti_labels"]
            ]
            if matching_labels:
                return f"Ignoring observable because it has the following label(s): {', '.join(matching_labels)}"

        if (
            entity_type == "observable"
            and not obs_indicators
            and not self.create_obs_sightings
        ):
            self.helper.connector_logger.info(
                "Observable has no indicators and WAZUH_CREATE_OBSERVABLE_SIGHTINGS is false"
            )
            return "Observable has no indicators"

        if api_searchable_entity_type(entity["entity_type"]):
            if not self.wazuh:
                self.helper.log_info(
                    f'Cannot search for {entity["entity_type"]} because WAZUH_API_USE is false'
                )
            else:
                self._query_api(entity, stix_entity)

        result = self.alert_searcher.search(entity=entity, stix_entity=stix_entity)
        if result is None:
            # Even though the entity is supported (an exception is throuwn
            # otherwise), not all entities contains information that is
            # searchable in Wazuh. There may also not be enough information to
            # perform a search that is targeted enough. This is not an error:
            return f"{entity['entity_type']} has no queryable data"

        if result["_shards"]["failed"] > 0:
            for failure in result["_shards"]["failures"]:
                self.helper.connector_logger.error(f"Query failure: {failure}")

        hits = result["hits"]["hits"]
        if not hits:
            return "No hits found"

        if (
            self.hits_abort_limit is not None
            and (hit_count := result["hits"]["total"]["value"]) > self.hits_abort_limit
        ):
            raise ValueError(
                f"Too many hits ({hit_count}) > {self.hits_abort_limit}): aborting"
            )

        # Use a helper module to create as few sighting objects as possible,
        # and modify their first_seen, last_seen and count instead:
        sightings_collector = SightingsCollector(observable_id=entity["standard_id"])
        agents = {}
        # The complete STIX bundle to send:
        bundle = [self.author, self.siem_system]
        for hit in hits:
            try:
                s = hit["_source"]
                if (
                    has(s, ["agent", "id"])
                    and self.agents_as_systems
                    # Do not create systems for master/worker, use the Wazuh system instead:
                    and int(s["agent"]["id"]) > 0
                ):
                    agents[s["agent"]["id"]] = sighter = self.create_agent_stix(hit)
                else:
                    sighter = self.siem_system

                sightings_collector.add(
                    timestamp=s["@timestamp"],
                    sighter=sighter,
                    alert=hit,
                )

            except (IndexError, KeyError) as e:
                raise OpenSearchClient.ParseError(
                    "Failed to parse _source: Unexpected JSON structure"
                ) from e

        # TODO: Use in incident and add as targets(?):
        if self.create_agent_ip_obs:
            bundle += self.create_agent_addr_obs(alerts=hits)
        if self.create_agent_host_obs:
            bundle += self.create_agent_hostname_obs(alerts=hits)

        # TODO: doesn't seem to work? Or bug in OpenCTI. Anyway, add STIXList
        # as type hint to bundle everywhere before continuing working on this:
        # bundle = add_incidents_to_note_refs(bundle)

        # FIXME: WAZUH_INCIDENT_CREATE_MODE=per_sighting produces missing ref
        # errors unless dummy indicator exists. Update: might be random and
        # unrelated.
        sighting_ids = []
        for sighter_id, meta in sightings_collector.collated().items():
            sighting = self.create_sighting_stix(sighter_id=sighter_id, metadata=meta)
            sighting_ids.append(sighting.id)
            bundle += [sighting] + self.create_sighting_alert_notes(
                entity=entity, sighting_id=sighting.id, metadata=meta
            )

        ###############
        # hostname seems to be the target, not a system
        # relation "uses" on attack pattern (mitre)
        #
        # Issues:
        #   When creating alerts, double alerts is an issue when rule engine is enabled
        #   The indicator is not available yet when working with the observable (timing issue)
        # Setting: incident for sightings in obs
        # Setting: Incident for sightings in obs with indicator
        # Setting: One incident per alert rule.id
        # Setting: Include rule ids, exclude rule ids
        # Setting: Agents as hostnames
        # Setting: Agent IP as observable
        # Setting: max_ext_ref per rule_id, per search?. same for note
        # Setting for limiting notes per sighting (0 disables notes for sightings)
        # Setting for limiting ext.refs. per sighting (0 disables)
        # Setting for adhering to detection, valid_until, min score(?)
        #
        # Create external reference to wazuh with the query that was ran (discover? custom columns?)
        # Look into how playbooks can be used
        # Add mitre connector and import tactics etc.
        # Look through wazuh rules to find occurances of usernames, addresses etc.
        ###############

        alerts_by_rule_id = sightings_collector.alerts_by_rule_id()
        counts = {rule_id: len(alerts) for rule_id, alerts in alerts_by_rule_id.items()}
        self.helper.log_debug(f"COUNTS: {counts}")

        if (
            self.require_indicator_for_incidents
            and entity_type == "observable"
            and not obs_indicators
        ):
            self.helper.connector_logger.info(
                "Not creating incident because entity is an observable, an indicator is required and no indicators are found"
            )
        else:
            bundle += self.create_incidents(
                entity=entity,
                obs_indicators=obs_indicators,
                result=result,
                sightings_meta=sightings_collector,
            )

        bundle += [
            self.create_summary_note(
                result=result,
                sightings_meta=sightings_collector,
                refs=[sightings_collector.observable_id()]
                + (sighting_ids if self.create_sighting_summary else [])
                + [
                    obj.id
                    for obj in bundle
                    if self.create_incident_summary and obj.type == "incident"
                ],
            )
        ]

        bundle += list(agents.values())
        bundle += self.relate_agents_to_siem(list(agents.values()), self.siem_system)

        # NOTE: This must be the lastly created bundle, because it references
        # all other objects in the bundle list:
        if self.create_incident_response and any(
            isinstance(obj, stix2.Incident) for obj in bundle
        ):
            bundle += self.create_incident_response_case(
                entity=entity, result=result, bundle=bundle
            )

        if (
            self.bundle_abort_limit is not None
            and (bundle_count := len(bundle)) > self.bundle_abort_limit
        ):
            raise ValueError(
                f"Bundle is too large ({bundle_count} > {self.bundle_abort_limit}): aborting"
            )

        sent_count = len(
            self.helper.send_stix2_bundle(
                self.helper.stix2_create_bundle(bundle),  # type: ignore
                update=True,
            )
        )
        return f"Sent {sent_count} STIX bundle(s) for worker import"

    def entity_indicators(self, entity: dict) -> list[dict]:
        if "indicators" not in entity:
            return []
        return [
            ind
            for obj in entity["indicators"]
            if (ind := self.helper.api.indicator.read(id=obj["id"])) is not None
            if ind is not None
        ]

    def _query_api(self, entity: dict, stix_entity: dict):
        # TODO: handle results. Refactor this file first
        # TODO: Ideally log a message that WAZUH_API_USE is false if a
        # supported, and raise ValueError if non-supported entity is passed
        if not self.wazuh:
            return None
        match entity["entity_type"]:
            case "Software":
                results = self.wazuh.find_package(
                    stix_entity["name"], stix_entity.get("version")
                )
                self.helper.log_debug(results)
                # for (agent, package) in results:

            case _:
                return None

    def create_agent_stix(self, alert):
        s = alert["_source"]
        id = s["agent"]["id"]
        name = s["agent"]["name"]
        return stix2.Identity(
            # id=Identity.generate_id(name, "system"),
            id=Identity.generate_id(id, "system"),
            **self.stix_common_attrs,
            name=name,
            identity_class="system",
            description=self.generate_agent_md_tables(id),
        )

    def relate_agents_to_siem(self, agents: list[stix2.Identity], siem: stix2.Identity):
        return [
            stix2.Relationship(
                id=StixCoreRelationship.generate_id("relates-to", siem.id, agent.id),
                created=agent.created,
                **self.stix_common_attrs,
                relationship_type="related-to",
                source_ref=agent.id,
                target_ref=siem.id,
            )
            for agent in agents
        ]

    def generate_agent_md_tables(self, agent_id: str):
        if self.wazuh and agent_id in self.wazuh.state.agents and self.enrich_agent:
            agent = self.wazuh.state.agents[agent_id]
            return (
                "|Key|Value|\n"
                "|---|-----|\n"
                f"|ID|{agent.id}|\n"
                f"|Name|{agent.name}|\n"
                f"|Status|{agent.status if agent.status is not None else ''}|\n"
                f"|OS name|{agent.os.name if agent.os is not None else ''}|\n"
                f"|OS version|{agent.os.version if agent.os is not None else ''}|\n"
                f"|Agent version|{agent.version}|\n"
                f"|IP address|{agent.ip}|\n"
            )
        else:
            return "|Key|Value|\n" "|---|-----|\n" f"|ID|{agent_id}|\n"

    def create_sighting_stix(
        self, *, sighter_id: str, metadata: SightingsCollector.Meta
    ):
        return stix2.Sighting(
            id=StixSightingRelationship.generate_id(
                metadata.observable_id,
                sighter_id,
                metadata.first_seen,
                metadata.last_seen,
            ),
            **self.stix_common_attrs,
            first_seen=metadata.first_seen,
            last_seen=metadata.last_seen,
            count=metadata.count,
            where_sighted_refs=[sighter_id],
            # Use a dummy indicator since this field is required:
            sighting_of_ref=DUMMY_INDICATOR_ID,
            custom_properties={"x_opencti_sighting_of_ref": metadata.observable_id},
            # FIXME: External references has stopped working (takes a second enrichment run):
            external_references=self.create_sighting_ext_refs(metadata=metadata),
        )

    def create_sighting_ext_refs(self, *, metadata: SightingsCollector.Meta):
        ext_ref_count = 0
        return [
            self.create_alert_ext_ref(alert=alert)
            for alerts in metadata.alerts.values()
            # In addition to limit the total number of external references,
            # also limit them per alert rule (pick the last N alerts to get
            # the latest alerts):
            for alert in alerts[-self.max_extrefs_per_alert_rule :]
            if (ext_ref_count := ext_ref_count + 1) <= self.max_extrefs
        ]

    def create_alert_ext_ref(self, *, alert):
        return stix2.ExternalReference(
            source_name="Wazuh alert",
            description=alert_md_table(alert),
            url=urljoin(
                self.app_url,  # type: ignore
                f'app/discover#/context/wazuh-alerts-*/{alert["_id"]}?_a=(columns:!(_source),filters:!())',
            ),
        )

    def create_sighting_alert_notes(
        self, *, entity: dict, sighting_id: str, metadata: SightingsCollector.Meta
    ):
        note_count = 0
        return [
            self.create_alert_note(
                entity=entity,
                sighting_id=sighting_id,
                alert=alert,
                limit_info=capped_at,
            )
            for alerts in metadata.alerts.values()
            # In addition to limit the total number of external references,
            # also limit them per alert rule (pick the last N alerts to get
            # the latest alerts):
            for i, alert in enumerate(alerts[-self.max_notes_per_alert_rule :])
            for capped_at in (
                (i + 1, len(alerts), self.max_notes_per_alert_rule)
                if len(alerts) > self.max_notes_per_alert_rule
                else None,
            )
            if (note_count := note_count + 1) <= self.max_notes
        ]

    def create_alert_note(
        self,
        *,
        entity: dict,
        sighting_id,
        alert,
        limit_info: tuple[int, int, int] | None,
    ):
        s = alert["_source"]
        sighted_at = s["@timestamp"]
        obs_values = entity_values(entity)
        alert_json = json.dumps(s, indent=2)
        capped_info = (
            [
                (
                    str("Count"),
                    f"{limit_info[0]} of {limit_info[1]} (limited to {limit_info[2]})",
                )
            ]
            if limit_info
            else []
        )
        return stix2.Note(
            id=Note.generate_id(
                created=sighted_at,
                content=alert_json,
            ),
            created=sighted_at,
            **self.stix_common_attrs,
            abstract=f"""Wazuh alert "{s['rule']['description']}" for sighting at {sighted_at}""",
            content="## Summary\n\n"
            + alert_md_table(alert, capped_info)
            + (
                "\n\n"
                # These matches do not reflect how the query matched, but it is still useful:
                "## Matches\n"
                "\n\n"
                "|Field|Match|\n"
                "|-----|-----|\n"
                + "".join(
                    f"|{field}|{match}|\n"
                    for field, match in search_in_object_multi(
                        alert["_source"], *obs_values, exclude_fields=["full_log"]
                    ).items()
                )
                + "\n\n"
                "## Alert\n"
                "\n\n"
                f"```json\n{alert_json}\n```"
            ),
            object_refs=[entity["standard_id"], sighting_id],
            external_references=[self.create_alert_ext_ref(alert=alert)],
            allow_custom=True,
            note_types=["analysis"],
        )

    def create_summary_note(
        self,
        *,
        result: dict,
        sightings_meta: SightingsCollector,
        refs: list[str],
    ):
        run_time = datetime.now()
        run_time_string = run_time.isoformat() + "Z"
        abstract = f"Wazuh enrichment at {run_time_string}"
        hits_returned = len(result["hits"]["hits"])
        total_hits = result["hits"]["total"]["value"]
        # TODO: link to query if a link to opensearch is possible
        content = (
            "## Wazuh enrichment summary\n"
            "\n\n"
            "|Key|Value|\n"
            "|---|---|\n"
            f"|Time|{run_time_string}|\n"
            f"|Duration|{result['took']} ms|\n"
            f"|Hits returned|{hits_returned}|\n"
            f"|Total hits|{total_hits}|\n"
            f"|Max hits|{self.hits_limit}|\n"
            f"|**Dropped**|**{total_hits - hits_returned}**|\n"
            f"|Search since|{self.search_after.isoformat() + 'Z' if self.search_after else '–'}|\n"
            f"|Include filter|{json.dumps(self.search_include) if self.alert_searcher.opensearch.include_match else ''}|\n"
            f"|Exclude filter|{json.dumps(self.search_exclude) if self.alert_searcher.opensearch.exclude_match else ''}|\n"
            f"|Connector v.|{self.CONNECTOR_VERSION}|\n"
            "\n"
            "### Alerts overview\n"
            "\n"
            "|Rule|Level|Count|Earliest|Latest|Description|\n"
            "|----|-----|-----|--------|------|-----------|\n"
        ) + "".join(
            f"{rule_id}|{level}|{len(alerts)}{'+' if total_hits > hits_returned else ''}|{sightings_meta.first_seen(rule_id)}|{sightings_meta.last_seen(rule_id)}|{rule_desc}|\n"
            for rule_id, alerts in sightings_meta.alerts_by_rule_id().items()
            for level in (alerts[0]["_source"]["rule"]["level"],)
            for rule_desc in (
                common_prefix_string(
                    [alert["_source"]["rule"]["description"] for alert in alerts]
                ),
            )
        )

        return stix2.Note(
            id=Note.generate_id(created=run_time_string, content=content),
            created=run_time_string,
            **self.stix_common_attrs,
            abstract=abstract,
            content=content,
            object_refs=refs,
            allow_custom=True,
            note_types=["analysis"],
        )

    def create_incidents(
        self,
        *,
        entity: dict,
        obs_indicators: list[dict],
        result: dict,
        sightings_meta: SightingsCollector,
    ):
        def log_skipped_incident_creation(level: int):
            self.helper.connector_logger.info(
                f"Not creating incident because rule level below threshold: {level} < {self.create_incident_threshold}"
            )
            return True

        sightings = sightings_meta.collated()
        incidents = []
        bundle = []
        total_sightings = sum(map(lambda s: s.count, sightings.values()))
        total_systems = len(sightings.keys())
        query_hits_dropped = (
            len(result["hits"]["hits"]) < result["hits"]["total"]["value"]
        )
        # TODO:
        # severity = cvss3_to_severity(alert entity['entity_type'] == 'Vulnerability'
        match self.create_incident:
            case "per_query":
                if (
                    level := sightings_meta.max_rule_level()
                ) < self.create_incident_threshold:
                    log_skipped_incident_creation(level)
                    return []

                incident_name = f"Wazuh alert: {entity_name_value(entity)} sighted"
                incident = stix2.Incident(
                    id=Incident.generate_id(
                        incident_name, sightings_meta.last_sighting_timestamp()
                    ),
                    created=sightings_meta.last_sighting_timestamp(),
                    **self.stix_common_attrs,
                    incident_type="alert",
                    name=incident_name,
                    description=f"Observable {entity_name_value(entity)} has been sighted a total of {total_sightings}{'+' if query_hits_dropped else ''} time(s) in {total_systems} system(s)",
                    allow_custom=True,
                    # The following are extensions:
                    severity=rule_level_to_severity(sightings_meta.max_rule_level()),
                    first_seen=sightings_meta.first_seen(),
                    last_seen=sightings_meta.last_seen(),
                    source=self.system_name,
                )
                incidents = [incident]
                bundle = (
                    incidents
                    + self.create_incident_relationships(
                        incident=incident,
                        entity=entity,
                        obs_indicators=obs_indicators,
                        sighters=list(sightings.keys()),
                    )
                    + self.enricher.enrich_incident(
                        incident=incident, alerts=sightings_meta.alerts()
                    )
                )

            case "per_sighting":
                for sighter_id, meta in sightings.items():
                    if (level := meta.max_rule_level) < self.create_incident_threshold:
                        log_skipped_incident_creation(level)
                        continue

                    incident_name = f"Wazuh alert: {entity_name_value(entity)} sighted in {meta.sighter_name}"
                    incident = stix2.Incident(
                        id=Incident.generate_id(incident_name, meta.last_seen),
                        created=meta.last_seen,
                        **self.stix_common_attrs,
                        incident_type="alert",
                        name=incident_name,
                        description=f"Observable {entity_name_value(entity)} has been sighted {meta.count}{'+' if query_hits_dropped else ''} time(s) in {meta.sighter_name}",
                        allow_custom=True,
                        # The following are extensions:
                        severity=rule_level_to_severity(meta.max_rule_level),
                        first_seen=meta.first_seen,
                        last_seen=meta.last_seen,
                        source=self.system_name,
                    )
                    incidents.append(incident)
                    bundle.append(incident)
                    bundle += self.create_incident_relationships(
                        incident=incident,
                        entity=entity,
                        obs_indicators=obs_indicators,
                        sighters=[sighter_id],
                    )
                    bundle += self.enricher.enrich_incident(
                        incident=incident,
                        alerts=[
                            alert for alerts in meta.alerts.values() for alert in alerts
                        ],
                    )

            case "per_alert_rule":
                for rule_id, meta in sightings_meta.alerts_by_rule_id_meta().items():
                    # Alerts are grouped by ID and all have the same level, so just pick one:
                    alerts_level = meta["alerts"][0]["_source"]["rule"]["level"]
                    if alerts_level < self.create_incident_threshold:
                        log_skipped_incident_creation(alerts_level)
                        continue

                    incident_name = f"Wazuh alert: {entity_name_value(entity)} sighted"
                    # Alerts may have different description even if they have
                    # the same level. Pick the longest common prefix:
                    alerts_desc = common_prefix_string(
                        [
                            alert["_source"]["rule"]["description"]
                            for alert in meta["alerts"]
                        ]
                    )
                    incident = stix2.Incident(
                        id=Incident.generate_id(incident_name, meta["last_seen"]),
                        created=meta["last_seen"],
                        **self.stix_common_attrs,
                        incident_type="alert",
                        name=incident_name,
                        description=f"""Observable {entity_name_value(entity)} has been sighted {len(meta['alerts'])}{'+' if query_hits_dropped else ''} time(s) in alert rule {rule_id}: "{alerts_desc}\"""",
                        allow_custom=True,
                        # The following are extensions:
                        severity=rule_level_to_severity(alerts_level),
                        first_seen=meta["first_seen"],
                        last_seen=meta["last_seen"],
                        source=self.system_name,
                    )
                    incidents.append(incident)
                    bundle.append(incident)
                    bundle += self.create_incident_relationships(
                        incident=incident,
                        entity=entity,
                        obs_indicators=obs_indicators,
                        sighters=meta["sighters"],
                    )
                    bundle += self.enricher.enrich_incident(
                        incident=incident, alerts=[alert for alert in meta["alerts"]]
                    )

            case "per_alert":
                for sighter_id, meta in sightings_meta.alerts_by_sighter_meta().items():
                    incident_name = f"Wazuh alert: {entity_name_value(entity)} sighted in {meta['sighter_name']}"
                    incidents = [
                        stix2.Incident(
                            id=Incident.generate_id(incident_name, sighted_at),
                            created=sighted_at,
                            **self.stix_common_attrs,
                            incident_type="alert",
                            name=incident_name,
                            description=f"""Observable {entity_name_value(entity)} has been sighted in alert rule {rule_id}: "{rule_desc}\"""",
                            allow_custom=True,
                            # The following are extensions:
                            severity=rule_level_to_severity(rule_level),
                            first_seen=sighted_at,
                            last_seen=sighted_at,
                            source=self.system_name,
                        )
                        for alert in meta["alerts"]
                        for sighted_at in (alert["_source"]["@timestamp"],)
                        for rule_id in (alert["_source"]["rule"]["id"],)
                        for rule_desc in (alert["_source"]["rule"]["description"],)
                        for rule_level in (alert["_source"]["rule"]["level"],)
                        if (
                            rule_level >= self.create_incident_threshold
                            # Just a hack to log some info:
                            or not log_skipped_incident_creation(rule_level)
                        )
                    ]

                    bundle += incidents

                    for incident in incidents:
                        bundle += self.create_incident_relationships(
                            incident=incident,
                            entity=entity,
                            obs_indicators=obs_indicators,
                            sighters=[sighter_id],
                        )

                    # TODO: Implement (this solution doesn't work):
                    # bundle += [
                    #    enrichment
                    #    for filtered_alerts in [
                    #        alert
                    #        for alert in meta["alerts"]
                    #        if alert["_source"]["rule"]["level"]
                    #        >= self.create_incident_threshold
                    #    ]
                    #    for pair in zip(incidents, filtered_alerts, strict=True)
                    #    for incident, alerts in (pair,)
                    #    for enrichment in self.enricher.enrich_incident(
                    #        incident=incident, alerts=alerts
                    #    )
                    # ]

            case _:
                raise ValueError(
                    f'WAZUH_INCIDENT_CREATE_MODE "{self.create_incident}" is invalid'
                )

        return bundle

    def create_incident_relationships(
        self,
        *,
        incident: stix2.Incident,
        entity: dict,
        obs_indicators: list[dict],
        sighters: list[str],
    ):
        return (
            [
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        incident_entity_relation_type(entity),
                        incident.id,
                        entity["standard_id"],
                    ),
                    created=incident.created,
                    **self.stix_common_attrs,
                    relationship_type=incident_entity_relation_type(entity),
                    source_ref=incident.id,
                    target_ref=entity["standard_id"],
                )
            ]
            + [
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "targets",
                        incident.id,
                        sighter,
                    ),
                    created=incident.created,
                    **self.stix_common_attrs,
                    relationship_type="targets",
                    source_ref=incident.id,
                    target_ref=sighter,
                )
                for sighter in sighters
            ]
            + [
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "indicates",
                        ind["standard_id"],
                        incident.id,
                    ),
                    created=incident.created,
                    **self.stix_common_attrs,
                    relationship_type="indicates",
                    source_ref=ind["standard_id"],
                    target_ref=incident.id,
                )
                for ind in obs_indicators
            ]
        )

    def create_incident_response_case(
        self, *, entity: dict, result: dict, bundle: list[Any]
    ):
        incidents = [obj for obj in bundle if isinstance(obj, stix2.Incident)]
        timestamp = max(incident.created for incident in incidents)
        severity = max_severity([incident.severity for incident in incidents])
        sightings_count = reduce(
            lambda sum, sighting: sum + sighting.count,
            [obj for obj in bundle if isinstance(obj, stix2.Sighting)],
            0,
        )
        hits_dropped = result["hits"]["total"]["value"] > len(result["hits"]["hits"])
        name = f"{entity_name_value(entity)} sighted {sightings_count}{'+' if hits_dropped else ''} time(s)"
        refs = bundle + [entity["standard_id"]]
        refs.remove(self.author)
        return (
            CustomObjectCaseIncident(
                id=CaseIncident.generate_id(name, timestamp),
                name=name,
                description="FIXME",
                severity=severity,
                priority=priority_from_severity(severity),
                **self.stix_common_attrs,
                # This should be okay, because these refs can be any of SCO, SDO and SRO:
                object_refs=refs,
            ),
        )

    def create_agent_addr_obs(self, *, alerts: list[dict]):
        agents = {
            agent["id"]: {
                "name": agent["name"],
                "ip": ipaddress.ip_address(agent["ip"]),
                "standard_id": Identity.generate_id(agent["id"], "system"),
            }
            for alert in alerts
            for agent in (alert["_source"]["agent"],)
            if int(agent["id"]) > 0 and "ip" in agent
        }
        if self.wazuh and self.enrich_agent:
            for id, agent in agents.copy().items():
                if id in self.wazuh.state.agents:
                    api_agent = self.wazuh.state.agents[id].model_dump(
                        include={"name", "ip", "scan_time"}
                    )
                    # The agent has changed its address at some point in time.
                    # Add the new address as well:
                    if api_agent["ip"] != agent["ip"]:
                        # Createa new key to be able to add the new agent metadata:
                        agents[id + str(api_agent["ip"])] = api_agent | {
                            "standard_id": agent["standard_id"],
                            "is_new": True,
                        }
                    else:
                        # Add new metadata:
                        agents[id] |= api_agent

        bundle = []
        earliest = min(alert["_source"]["@timestamp"] for alert in alerts)
        latest = max(alert["_source"]["@timestamp"] for alert in alerts)
        # STIX doesn't accept start == stop, so remove stop if they are the same:
        if latest == earliest:
            latest = None

        for agent in agents.values():
            SCO = (
                stix2.IPv4Address
                if type(agent["ip"]) is ipaddress.IPv4Address
                else stix2.IPv6Address
            )
            addr = SCO(
                value=agent["ip"],
                allow_custom=True,
                **self.stix.common_properties,
                labels=self.stix.sco_labels,
            )
            rel = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", agent["standard_id"], addr.id
                ),
                **self.stix.common_properties,
                relationship_type="related-to",
                source_ref=agent["standard_id"],
                target_ref=addr.id,
                # If this is a new entry based off of the Wazuh API, don't use
                # the alert timestamp:
                start_time=(None if agent.get("is_new") else earliest),
                # If the agent was recently queried using the API, use the query time:
                stop_time=(
                    api_latest
                    if "scan_time" in agent
                    and latest
                    and (api_latest := agent["scan_time"].isoformat() + "Z") > latest
                    else latest
                ),
                description="The Wazuh agent had this IP address in the given time frame",
            )
            bundle.append(addr)
            bundle.append(rel)

        return bundle

    def create_agent_hostname_obs(self, *, alerts: list[dict]):
        agents = {
            agent["id"]: {
                "name": agent["name"],
                "standard_id": Identity.generate_id(agent["id"], "system"),
            }
            for alert in alerts
            for agent in (alert["_source"]["agent"],)
            if int(agent["id"]) > 0
        }
        if self.wazuh and self.enrich_agent:
            for id, agent in agents.copy().items():
                if id in self.wazuh.state.agents:
                    api_agent = self.wazuh.state.agents[id].model_dump(
                        include={"name", "scan_time"}
                    )
                    # The agent has changed hostname at some point in time. Add
                    # the new hostname as well:
                    if api_agent["name"] != agent["name"]:
                        # Createa new key to be able to add the new agent metadata:
                        agents[id + api_agent["name"]] = api_agent | {
                            "standard_id": agent["standard_id"]
                        }
                    else:
                        # Add new metadata:
                        agents[id] |= api_agent

        bundle = []
        earliest = min(alert["_source"]["@timestamp"] for alert in alerts)
        latest = max(alert["_source"]["@timestamp"] for alert in alerts)
        # STIX doesn't accept start == stop, so remove stop if they are the same:
        if latest == earliest:
            latest = None

        for agent in agents.values():
            hostname = CustomObservableHostname(
                value=agent["name"],
                allow_custom=True,
                **self.stix.common_properties,
                labels=self.stix.sco_labels,
            )
            rel = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", agent["standard_id"], hostname.id
                ),
                **self.stix.common_properties,
                relationship_type="related-to",
                source_ref=agent["standard_id"],
                target_ref=hostname.id,
                # If this is a new entry based off of the Wazuh API, don't use
                # the alert timestamp:
                start_time=(None if agent.get("is_new") else earliest),
                # If the agent was recently queried using the API, use the query time:
                stop_time=(
                    api_latest
                    if "scan_time" in agent
                    and latest
                    and (api_latest := agent["scan_time"].isoformat() + "Z") > latest
                    else latest
                ),
                description="The Wazuh agent had this hostname in the given time frame",
            )
            bundle.append(hostname)
            bundle.append(rel)

        return bundle
