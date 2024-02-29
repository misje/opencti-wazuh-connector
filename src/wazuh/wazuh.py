import json
import stix2
import yaml
import dateparser
import re
from .opensearch import OpenSearchClient
from pathlib import Path
from pycti import (
    Identity,
    Incident,
    Note,
    OpenCTIConnectorHelper,
    OpenCTIMetricHandler,
    StixCoreRelationship,
    StixSightingRelationship,
    get_config_variable,
)
from typing import Final
from hashlib import sha256
from datetime import datetime
from urllib.parse import urljoin
from os.path import basename

# TODO:
#  metrics: run_coiunt, bundle_send, record_send, error_count, client_error_count
#  state: idle, running, stopped
#
# Populate agents using agent metadata?
# SETTING: agent_labels: comma-separated list of labels to attach to agents
# SETTING: siem_labels: comma-separated list of labels to attach to wazuh identity
# Search include/exclue in setting level (add wazuh-opencti as default)
# tlp marking (config)
# Create wazuh integration that creates incidents in opencti
# get_config_variable with required doesn't throw if not set


# UUID_RE = r"^a[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$"
# STIX_ID_REGEX = re.compile(f".+--{UUID_RE}", re.IGNORECASE)


class SightingsCollector:
    """
    Helper module to reduce the number of sightings to one instance per SDO

    When a sighting is added using add(), the metadata passed to the function
    is added to a dict. Any subsequent calls for the same sighter_id updates
    first_seen, last_seen and count accordingly.
    """

    def __init__(self, *, observable_id: str):
        self._sightings = {}
        # This module will only be used for one SCO at a time:
        self._observable_id = observable_id
        self._latest = ""

    def add(self, *, timestamp: str, sighter_id: str, alert: dict):
        """
        Add or update metadata for sightings of an observable in sighter_id
        """
        if sighter_id in self._sightings:
            self._sightings[sighter_id]["first_seen"] = min(
                self._sightings[sighter_id]["first_seen"], timestamp
            )
            self._sightings[sighter_id]["last_seen"] = max(
                self._sightings[sighter_id]["last_seen"], timestamp
            )
            self._sightings[sighter_id]["count"] += 1
            self._sightings[sighter_id]["alerts"][timestamp] = alert
            if timestamp > self._latest:
                self._latest = timestamp
        else:
            self._sightings[sighter_id] = {
                "first_seen": timestamp,
                "last_seen": timestamp,
                "count": 1,
                "observable_id": self._observable_id,
                "alerts": {timestamp: alert},
            }
            self._latest = timestamp

    def collated(self):
        return self._sightings

    def last_sighting_timestamp(self):
        return self._latest

    def alerts_by_rule_id(self):
        """
        Return a dict with alerts grouped by rule_id

        The keys are Wazuh rule IDs as strings (since they are strings in Wazuh). The values are arrays of dicts, containing all alerts with that rule ID.
        Example: { "1234": [{…}, {…}] "1235": […] }
        """
        return {
            rule_id: [
                alert for alert in alerts if alert["_source"]["rule"]["id"] == rule_id
            ]
            for sighting in self._sightings.values()
            for alerts in (sighting["alerts"].values(),)
            for alert in alerts
            for rule_id in (alert["_source"]["rule"]["id"],)
        }


def has(obj: dict, spec: list[str], value=None):
    """
    Test whether obj contains a specific structure

    Examples:
    `obj = {"a": {"b": 42}`
    `has(obj, ['a'])` returns true
    `has(obj, ['b'])` returns false
    `has(obj, ['a', 'b'])` returns true
    `has(obj, ['a', 'b'], 43)` returns false
    `has(obj, ['a', 'b'], 42)` returns true
    """
    if not spec:
        return obj == value if value is not None else True
    try:
        key, *rest = spec
        return has(obj[key], rest, value=value)
    except (KeyError, TypeError):
        return False


# def has_any(obj, spec, values:list|None = None):
#    if not spec:
#        return any(obj == value for value in values) if values is not None else True
#    try:
#        key, *rest = spec
#        return has_any(obj[key], rest, values=values)
#    except (KeyError, TypeError):
#        return False


def has_any(obj: dict, spec1: list[str], spec2: list[str]):
    """
    Test whether an object contains a specific structure

    Test whether spec1 contains a specific structure (a "JSON path"). Then, test whether the resulting object has any of the keys listed in spec2. Example:

    `has_any({"a": {"b": {"d": 1, "e": 2}}}, ["a", "b"], ["c", "d"])` returns true, because "b" exists in "a", and "a" exists in obj, and either "c" or "d" exists in "b".
    """
    if not spec1:
        return any(key in obj for key in spec2)
    try:
        key, *rest = spec1
        return has_any(obj[key], rest, spec2)
    except (KeyError, TypeError):
        return False


def parse_config_datetime(value, setting_name):
    if value is None:
        return None

    timestamp = dateparser.parse(value)
    if not timestamp:
        raise ValueError(
            f'The config variable "{setting_name}" datetime expression cannot be parsed: "{value}"'
        )

    return timestamp


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
        self.DUMMY_INDICATOR_ID: Final[
            str
        ] = "indicator--220d5816-3786-5421-a6d3-fb149a0df54e"  # "indicator--c1034564-a9fb-429b-a1c1-c80116cc8e1e"

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
        self.max_tlp = get_config_variable(
            "WAZUH_MAX_TLP", ["wazuh", "max_tlp"], config, required=True
        )
        self.hits_limit = get_config_variable(
            "WAZUH_MAX_HITS", ["wazuh", "max_hits"], config, isNumber=True, default=10
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
        self.create_obs_note = get_config_variable(
            "WAZUH_CREATE_OBSERVABLE_NOTE",
            ["wazuh", "create_observable_note"],
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
        # Add moe useful meta to author?
        self.author = stix2.Identity(
            id=Identity.generate_id("Wazuh", "organization"),
            confidence=self.confidence,
            name="Wazuh",
            identity_class="organization",
            description="Wazuh",
        )
        self.siem_system = stix2.Identity(
            id=Identity.generate_id(self.system_name, "system"),
            created_by_ref=self.author["id"],
            confidence=self.confidence,
            name=self.system_name,
            identity_class="system",
        )
        self.app_url = get_config_variable(
            "WAZUH_APP_URL", ["wazuh", "app_url"], config, required=True
        )
        self.client = OpenSearchClient(
            helper=self.helper,
            url=get_config_variable(  # type: ignore
                "WAZUH_OPENSEARCH_URL",
                ["wazuh", "opensearch_url"],
                config,
                required=True,
            ),
            username=get_config_variable(  # type: ignore
                "WAZUH_USERNAME", ["wazuh", "username"], config, required=True
            ),
            password=get_config_variable(  # type: ignore
                "WAZUH_PASSWORD", ["wazuh", "password"], config, required=True
            ),
            limit=self.hits_limit if isinstance(self.hits_limit, int) else 10,
            index=get_config_variable(  # type: ignore
                "WAZUH_INDEX", ["wazuh", "index"], config, default="wazuh-alerts-*"
            ),
            search_after=self.search_after,
            include_match=parse_match_patterns(self.search_include),  # type: ignore
            exclude_match=parse_match_patterns(self.search_exclude),  # type: ignore
        )

    def start(self):
        self.helper.metric.state("idle")
        self.helper.listen(self.process_message)

    def process_message(self, data):
        # Use a helper class that ensures to always updates the running state of the connector, as well as incrementing the error count on uncaught exceptions:
        with self.MetricHelper(self.helper.metric):
            return self._process_message(data)

    def _process_message(self, data):
        entity = None
        if data["entity_id"].startswith("vulnerability--"):
            entity = self.helper.api.vulnerability.read(id=data["entity_id"])
        elif data["entity_id"].startswith("indicator--"):
            entity = self.helper.api.indicator.read(id=data["entity_id"])
        else:
            entity = self.helper.api.stix_cyber_observable.read(id=data["entity_id"])

        if entity is None:
            raise ValueError("Observable not found")

        # Figure out exactly what this does:
        enrichment = self.helper.get_data_from_enrichment(data, entity)
        stix_entity = enrichment["stix_entity"]
        obs_indicators = self.entity_indicators(entity)
        self.helper.log_debug(f"INDS: {obs_indicators}")

        if not obs_indicators or self.create_obs_sightings:
            self.helper.connector_logger.info(
                "Observable has no indicators and WAZUH_CREATE_OBSERVABLE_SIGHTINGS is false"
            )
            return "Observable has no indicators"

        self.helper.log_debug(f"ENTITY: {entity}")
        self.helper.log_debug(f"STIX_ENTITY: {stix_entity}")

        result = self._query_alerts(entity, stix_entity)
        if result is None:
            # This is not true. Revisit. Use exceptions?
            return "Failed to query Wazuh API"

        hits = result["hits"]["hits"]
        if not hits:
            return "No hits found"

        sighter = self.siem_system
        sightings_collector = SightingsCollector(observable_id=entity["standard_id"])
        agents = {}
        bundle = [self.author, self.siem_system]
        for hit in hits:
            try:
                s = hit["_source"]
                if (
                    has(s, ["agent", "id"])
                    and self.agents_as_systems
                    # Do not create systems for master/worker, use the Wazuh system instead:
                    and int(s["agent"]["id"])
                ):
                    agents[s["agent"]["id"]] = sighter = self.create_agent_stix(hit)

                sightings_collector.add(
                    timestamp=s["@timestamp"],
                    sighter_id=sighter.id,
                    alert=hit,
                )

            except (IndexError, KeyError):
                raise OpenSearchClient.ParseError(
                    "Failed to parse _source: Unexpected JSON structure"
                )

        # TODO: enrichment: create tool, like ssh, used in events like ssh logons

        sightings = sightings_collector.collated()
        for sighter_id, meta in sightings.items():
            bundle += [self.create_sighting_stix(sighter_id=sighter_id, metadata=meta)]
            # FIXME: create notes for every alert

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

        # Group alerts by ID and see how many are unique. Setting: inncident per rule id?
        # Add an enrichment function that creates mitre, tools etc for either when relevant fields are present or per rule id/group. Add a setting for each one (yaml only?)?
        # tool:
        #   uses → attack pattern

        alerts_by_rule_id = sightings_collector.alerts_by_rule_id()
        counts = {rule_id: len(alerts) for rule_id, alerts in alerts_by_rule_id.items()}
        self.helper.log_debug(f"COUNTS: {counts}")

        iname = f"Wazuh alert: something sighted in {sighter.name}"
        incident = stix2.Incident(
            id=Incident.generate_id(
                iname, sightings_collector.last_sighting_timestamp()
            ),
            created=sightings_collector.last_sighting_timestamp(),
            created_by_ref=self.author["id"],
            confidence=self.confidence,
            name=iname,
            description="Beskrivelsen",
        )
        bundle += [
            incident,
            stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", incident.id, entity["standard_id"]
                ),
                created=sightings_collector.last_sighting_timestamp(),
                created_by_ref=self.author["id"],
                confidence=self.confidence,
                relationship_type="related-to",
                source_ref=incident.id,
                target_ref=entity["standard_id"],
            ),
            stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "targets",
                    incident.id,
                    sighter.id,
                ),
                created=sightings_collector.last_sighting_timestamp(),
                created_by_ref=self.author["id"],
                confidence=self.confidence,
                relationship_type="targets",
                source_ref=incident.id,
                target_ref=sighter.id,
            ),
        ]
        bundle += [
            stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "indicates",
                    ind["standard_id"],  # type: ignore
                    incident.id,
                ),
                created=sightings_collector.last_sighting_timestamp(),
                created_by_ref=self.author["id"],
                confidence=self.confidence,
                relationship_type="indicates",
                source_ref=ind["standard_id"],  # type: ignore
                target_ref=incident.id,
            )
            for ind in obs_indicators
        ]

        # if self.alerts_as_notes:
        #    bundle += [
        #        self.create_note_stix(
        #            sighting_id=sighting.id,
        #            alert=hit,
        #        ),
        #    ]

        self.helper.log_debug(f"Sightings end count: {len(sightings)}")
        # TODO: Add note also for no hits:
        # FIXME: update to use metadata?
        #
        # if self.create_obs_note:
        #    bundle += [
        #        self.create_summary_note(
        #            result=result,
        #            observable_id=entity["standard_id"],
        #            sightings=sightings.values(),
        #        )
        #    ]

        bundle += list(agents.values())
        sent_count = len(
            self.helper.send_stix2_bundle(
                self.helper.stix2_create_bundle(bundle), update=True
            )
        )
        return f"Sent {sent_count} STIX bundle(s) for worker import"

    def entity_indicators(self, entity: dict) -> list[dict]:
        return [
            ind
            for obj in entity["indicators"]
            if (ind := self.helper.api.indicator.read(id=obj["id"])) is not None
            if ind is not None
        ]

    # TODO: when name is used, look for alias too?
    def _query_alerts(self, entity, stix_entity) -> dict | None:
        match entity["entity_type"]:
            case "StixFile" | "Artifact":
                if (
                    entity["entity_type"] == "StixFile"
                    and "name" in stix_entity
                    and not has_any(
                        stix_entity, ["hashes"], ["SHA-256", "SHA-1", "MD5"]
                    )
                ):
                    # Filanem: smbd.filename = name, smbd.operation = pwrite_send? etc.
                    return self.client.search_multi_glob(
                        # TODO: worthwhile? Add all permutations of slash types and fields? Not sure if regex is the way to go
                        # remember, fields here cannot have globs: raise if they do?
                        fields=["syscheck.path"],
                        value="*/" + stix_entity["name"],
                    )
                elif has(stix_entity, ["hashes", "SHA-256"]):
                    return self.client.search_multi(
                        fields=["*sha256*"], value=stix_entity["hashes"]["SHA-256"]
                    )
                elif has(stix_entity, ["hashes", "SHA-1"]):
                    return self.client.search_multi(
                        fields=["*sha1*"], value=stix_entity["hashes"]["SHA-1"]
                    )
                else:
                    self.helper.connector_logger.info(
                        "StixFile/Artifact has no queryable information"
                    )
                    return None

            # TODO: add setting that only looks up public addresses? (GeoLocation.countr_name exists?) Tested, not consistent enough
            case "IPv4-Addr" | "IPv6-Addr":
                fields = [
                    "*.ip",
                    "*.dest_ip",
                    "*.dstip",
                    "*.src_ip",
                    "*.srcip",
                    "*.ClientIP",
                    "*.ActorIpAddress",
                    "*.remote_ip",
                    "*.remote_ip_address",
                    "*.sourceIPAddress",
                    "*.source_ip_address",
                    "*.callerIp",
                    "*.ipAddress",
                    "data.win.eventdata.queryName",
                ]
                address = entity["observable_value"]
                if self.search_agent_ip:
                    return self.client.search_multi(
                        fields=fields,
                        value=address,
                    )
                else:
                    return self.client.search(
                        must={
                            "multi_match": {
                                "query": address,
                                "fields": fields,
                            }
                        },
                        must_not={"match": {"agent.ip": address}},
                    )
            case "Mac-Addr":
                return self.client.search_multi(
                    fields=[
                        "*.src_mac",
                        "*.srcmac",
                        "*.dst_mac",
                        "*.dstmac",
                        "*.mac",
                        "data.osquery.columns.interface",
                    ],
                    value=entity["observable_value"],
                )
            case "Network-Traffic":
                query = []
                if "src_ref" in stix_entity:
                    src_ip = self.helper.api.stix_cyber_observable.read(
                        id=stix_entity["src_ref"]
                    )
                    if src_ip and "value" in src_ip:
                        query.append(
                            {
                                "multi_match": {
                                    "query": src_ip["value"],
                                    "fields": ["*.src_ip", "*.srcip"],
                                }
                            }
                        )
                if "src_port" in stix_entity:
                    query.append(
                        {
                            "multi_match": {
                                "query": stix_entity["src_port"],
                                "fields": ["*.src_port", "*.srcport"],
                            }
                        }
                    )
                if "dst_ref" in stix_entity:
                    dest_ip = self.helper.api.stix_cyber_observable.read(
                        id=stix_entity["dst_ref"]
                    )
                    if dest_ip and "value" in dest_ip:
                        query.append(
                            {
                                "multi_match": {
                                    "query": dest_ip["value"],
                                    "fields": ["*.dest_ip", "*.dstip"],
                                }
                            }
                        )
                if "dst_port" in stix_entity:
                    query.append(
                        {
                            "multi_match": {
                                "query": stix_entity["dst_port"],
                                "fields": ["*.dest_port", "*.dstport"],
                            }
                        }
                    )

                if query:
                    return self.client.search(query)
                else:
                    self.helper.connector_logger.info(
                        "Network-Traffic has no queryable information"
                    )
                    return None
            # TODO: or remove from docker-compose:
            # case "Email-Addr":
            case "Domain-Name" | "Hostname":
                fields = [
                    "data.win.eventdata.queryName",
                    "data.dns.question.name",
                    "*.hostname",
                ]
                hostname = entity["observable_value"]
                if self.search_agent_name:
                    return self.client.search_multi(
                        fields=fields,
                        value=hostname,
                    )
                else:
                    return self.client.search(
                        must={
                            "multi_match": {
                                "query": hostname,
                                "fields": fields,
                            }
                        },
                        must_not={"match": {"agent.name": hostname}},
                    )
            case "Url":
                return self.client.search_multi(
                    fields=["*.url", "data.office365.SiteUrl"],
                    value=entity["observable_value"],
                )
            case "Directory":
                return self.client.search_multi(
                    fields=["*.path"],
                    value=stix_entity["path"],
                )
            case "Windows-Registry-Key":
                return self.client.search_multi(
                    fields=["data.win.eventdata.targetObject", "syscheck.path"],
                    value=stix_entity["key"],
                )
            case "Windows-Registry-Value-Type":
                hash = None
                match stix_entity["data_type"]:
                    case "REG_SZ" | "REG_EXPAND_SZ":
                        hash = sha256(stix_entity["data"].encode("utf-8")).hexdigest()
                    case "REG_BINARY":
                        # The STIX standard says that binary data can be in any form, but in order to be able to use this type of observable at all, support only hex strings:
                        try:
                            hash = sha256(
                                bytes.fromhex(stix_entity["data"])
                            ).hexdigest()
                        except ValueError:
                            self.helper.connector_logger.warning(
                                f"Windows-Registry-Value-Type binary string could not be parsed as a hex string: {stix_entity['data']}"
                            )
                    case _:
                        self.helper.connector_logger.info(
                            f"Windos-Registry-Value-Type of type {stix_entity['data_type']} is not supported"
                        )
                        return None

                return (
                    self.client.search_multi(
                        fields=["syscheck.sha256_after"], value=hash
                    )
                    if hash
                    else None
                )
            # TODO: use wazuh API?:
            case "Process":
                if "command_line" in stix_entity:
                    tokens = re.findall(
                        r"""("[^"]*"|'[^']*'|\S+)""", stix_entity["command_line"]
                    )
                    if len(tokens) < 1:
                        return {}

                    self.helper.log_debug(tokens)
                    command = basename(tokens[0])
                    args = [
                        re.sub(r"""^['"]|['"]$""", "", arg).replace("\\", "\\\\\\\\")
                        for arg in tokens[1:]
                    ]
                    # Todo: wildcard: case_insensitive: true
                    arg_queries = [
                        {"wildcard": {"data.win.eventdata.commandLine": f"*{arg}*"}}
                        for arg in args
                    ]
                    return self.client.search(
                        must=[
                            {
                                "wildcard": {
                                    "data.win.eventdata.commandLine": f"*{command}*"
                                }
                            }
                        ]
                        + arg_queries
                    )
                else:
                    self.helper.connector_logger.info(
                        "Process has no queryable information"
                    )
                    return None
            # case "Software":
            case "Vulnerability":
                return self.client.search_match(
                    {
                        "data.vulnerability.cve": stix_entity["name"],
                        "data.vulnerability.status": "Active",
                    }
                )
            case "User-Account":
                return self.client.search_multi(
                    fields=[
                        "*.dstuser",
                        "*.srcuser",
                        "*.user",
                        "*.userName",
                        "*.username",
                        "data.gcp.protoPayload.authenticationInfo.principalEmail",
                        "data.office365.UserId",
                    ],
                    value=stix_entity["account_login"],
                )
            case _:
                raise ValueError(
                    f'{entity["entity_type"]} is not a supported entity type'
                )

    def create_agent_stix(self, alert):
        s = alert["_source"]
        id = s["agent"]["id"]
        name = s["agent"]["name"]
        return stix2.Identity(
            # id=Identity.generate_id(name, "system"),
            id=Identity.generate_id(id, "system"),
            created_by_ref=self.author["id"],
            confidence=self.confidence,
            name=name,
            identity_class="system",
            description=f"Wazuh agent ID {id}",
        )

    def create_sighting_stix(self, *, sighter_id: str, metadata: dict):
        return stix2.Sighting(
            id=StixSightingRelationship.generate_id(
                metadata["observable_id"],
                sighter_id,
                metadata["first_seen"],
                metadata["last_seen"],
            ),
            # TODO: use this created date or real date?:
            # created=sighted_at,
            # TODO: put modified to created to avoid default NOW? Also elsewhere, in that case
            # modified=sighted_at,
            created_by_ref=self.author["id"],
            confidence=self.confidence,
            first_seen=metadata["first_seen"],
            last_seen=metadata["last_seen"],
            count=metadata["count"],
            where_sighted_refs=[sighter_id],
            # Use a dummy indicator since this field is required:
            sighting_of_ref=self.DUMMY_INDICATOR_ID,
            custom_properties={"x_opencti_sighting_of_ref": metadata["observable_id"]},
            # TODO: create once and
            external_references=[
                # TODO: timestamp and ordering? the key in 'alerts' is a timestamp:
                stix2.ExternalReference(
                    source_name="Wazuh",
                    description=f"Wazuh alert ID {alert['_id']}/{s['id']}: {s['rule']['description']}",
                    url=urljoin(
                        self.app_url,  # type: ignore
                        f'app/discover#/context/wazuh-alerts-*/{alert["_id"]}?_a=(columns:!(_source),filters:!())',
                    ),
                )
                for alert in metadata["alerts"].values()
                for s in (alert["_source"],)
            ],
        )

    def create_note_stix(self, *, sighting_id, alert):
        s = alert["_source"]
        sighted_at = s["@timestamp"]
        alert_json = json.dumps(s, indent=2)
        return stix2.Note(
            id=Note.generate_id(
                created=sighted_at,
                content=alert_json,
            ),
            # TODO: use this created date or real date?:
            created=sighted_at,
            created_by_ref=self.author["id"],
            confidence=self.confidence,
            abstract=f"""Wazuh alert "{s['rule']['description']}" (index {alert["_index"]}) for sighting at {sighted_at}""",
            content=f"```\n{alert_json}\n" "",
            object_refs=sighting_id,
        )

    def create_summary_note(
        self, *, result: dict, observable_id: str, sightings: list[stix2.Sighting]
    ):
        run_time = datetime.now()
        run_time_string = run_time.isoformat() + "Z"
        abstract = f"Wazuh enrichment at {run_time_string}"
        hits_returned = len(result["hits"]["hits"])
        total_hits = result["hits"]["total"]["value"]
        # TODO: shards info
        content = (
            "## Wazuh enrichment summary\n"
            "\n\n"
            "|Key|Value|\n"
            "|---|---|\n"
            f"|Time|{run_time_string}|\n"
            f"|Hits returned|{hits_returned}|\n"
            f"|Total hits|{total_hits}|\n"
            f"|Max hits|{self.hits_limit}|\n"
            f"|Dropped|{total_hits - hits_returned}|\n"
            f"|Search since|{self.search_after.isoformat() + 'Z' if self.search_after else '–'}|\n"
            f"|Include filter|{json.dumps(self.client.include_match) if self.client.include_match else ''}|\n"
            f"|Exclude filter|{json.dumps(self.client.exclude_match) if self.client.exclude_match else ''}|\n"
            f"|Connector v.|{self.CONNECTOR_VERSION}|\n"
            # Text about what was searched and how
        )
        return stix2.Note(
            id=Note.generate_id(created=run_time_string, content=content),
            created=run_time_string,
            created_by_ref=self.author["id"],
            confidence=self.confidence,
            abstract=abstract,
            content=content,
            object_refs=[observable_id] + list(map(lambda s: s.id, sightings)),
        )
