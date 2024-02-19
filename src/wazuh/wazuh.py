import json
import stix2
import yaml
import dateparser
from .opensearch import OpenSearchClient
from pathlib import Path
from pycti import (
    Identity,
    Note,
    OpenCTIConnectorHelper,
    StixSightingRelationship,
    get_config_variable,
)
from typing import Final
from hashlib import sha256
from datetime import datetime
from urllib.parse import urljoin

# TODO:
#  metrics: run_coiunt, bundle_send, record_send, error_count, client_error_count
#  state: idle, running, stopped
#
# Populate agents using agent metadata?
# SETTING: agent_labels: comma-separated list of labels to attach to agents
# SETTING: siem_labels: comma-separated list of labels to attach to wazuh identity
# Search include/exclue in setting level (add wazuh-opencti as default)
# tlp marking


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
    def __init__(self):
        self.CONNECTOR_VERSION: Final[str] = "0.0.1"
        self.DUMMY_INDICATOR_ID: Final[
            str
        ] = "indicator--220d5816-3786-5421-a6d3-fb149a0df54e"  # "indicator--c1034564-a9fb-429b-a1c1-c80116cc8e1e"

        config_file_path = Path(__file__).parent.parent.resolve() / "config.yml"
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
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
        self.url = get_config_variable(
            "WAZUH_OPENSEARCH_URL", ["wazuh", "opensearch_url"], config, required=True
        )
        self.app_url = get_config_variable(
            "WAZUH_APP_URL", ["wazuh", "app_url"], config, required=True
        )
        self.client = OpenSearchClient(
            helper=self.helper,
            url=self.url,
            username=get_config_variable(
                "WAZUH_USERNAME", ["wazuh", "username"], config, required=True
            ),
            password=get_config_variable(
                "WAZUH_PASSWORD", ["wazuh", "password"], config, required=True
            ),
            limit=self.hits_limit if isinstance(self.hits_limit, int) else 10,
            index=get_config_variable(
                "WAZUH_INDEX", ["wazuh", "index"], config, default="wazuh-alerts-*"
            ),
            search_after=self.search_after,
            include_match=parse_match_patterns(self.search_include),
            exclude_match=parse_match_patterns(self.search_exclude),
        )

    def _query_alerts(self, entity, stix_entity) -> dict | None:
        # FIXME: those returning {} must return a valid "hits" object, otherwise go for a "raise" alternative
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
                    return {}
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
                    return {}
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
                        return {}

                return (
                    self.client.search_multi(
                        fields=["syscheck.sha256_after"], value=hash
                    )
                    if hash
                    else {}
                )
            # TODO: use wazuh API?:
            # case "Process":
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

        # This is an error. exception instead?
        return None

    def _process_message(self, data):
        self.helper.metric.inc("run_count")
        self.helper.metric.state("running")

        entity = None
        if data["entity_id"].startswith("vulnerability--"):
            entity = self.helper.api.vulnerability.read(id=data["entity_id"])
        elif data["entity_id"].startswith("indicator--"):
            entity = self.helper.api.indicator.read(id=data["entity_id"])
        else:
            entity = self.helper.api.stix_cyber_observable.read(id=data["entity_id"])

        if entity is None:
            raise ValueError("Observable not found")

        enrichment = self.helper.get_data_from_enrichment(data, entity)
        stix_entity = enrichment["stix_entity"]

        result = self._query_alerts(entity, stix_entity)
        # TODO: exception instead of returning None:
        if result is None:
            self.helper.metric.state("idle")
            return "Failed to query Wazuh API"

        hits = result["hits"]["hits"]
        if not hits:
            self.helper.metric.state("idle")
            # FIXME: make show up as error in connector view:
            return "No hits found"

        sighter = self.siem_system
        sightings = []
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

                sighted_at = s["@timestamp"]
                sighting = self.create_sighting_stix(
                    sighter_id=sighter.id,
                    observable_id=entity["standard_id"],
                    alert=hit,
                )

                self.helper.connector_logger.debug(
                    f"Creating sighting in system {sighter.name} for alert at {sighted_at}"
                )
                sightings.append(sighting)
                bundle += [sighting]
                if self.alerts_as_notes:
                    bundle += [
                        self.create_note_stix(
                            sighting_id=sighting.id,
                            alert=hit,
                        ),
                    ]

                    # TODO: if a suitable object can be created for the wazuh alert, link the attack pattern (mitre):
                    # if has(s, ['rule', 'mitre']):
                    #    mitre = s['rule']['mitre']
                    #    attack_id = AttackPattern.generate_id(mitre['technique'],
                    #        x_mitre_id=mitre['id'])
                    #    bundle += [stix2.Relationship(
                    #               id = StixCoreRelationship.generate_id(
                    #                type='uses', source_ref=
                    #               relationship_type='uses',

                    #                    id =

            except (IndexError, KeyError):
                self.helper.connector_logger.error(
                    "[Wazuh]: Failed to parse result: Unexpected JSON structure"
                )
                # TODO: use elsewhere too:
                self.helper.metric.inc("client_error_count")

        # TODO: enrichment: create tool, like ssh, used in events like ssh logons

        # TODO: Add note also for no hits:
        if self.create_obs_note:
            bundle += [
                self.create_summary_note(
                    result=result,
                    observable_id=entity["standard_id"],
                    sightings=sightings,
                )
            ]

        bundle += list(agents.values())
        sent_count = len(
            self.helper.send_stix2_bundle(
                self.helper.stix2_create_bundle(bundle), update=True
            )
        )
        return f"Sent {sent_count} STIX bundle(s) for worker import"

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

    def create_sighting_stix(self, *, sighter_id, observable_id, alert):
        s = alert["_source"]
        sighted_at = s["@timestamp"]
        return stix2.Sighting(
            id=StixSightingRelationship.generate_id(
                observable_id,
                sighter_id,
                sighted_at,
                sighted_at,
            ),
            # TODO: use this created date or real date?:
            created=sighted_at,
            created_by_ref=self.author["id"],
            confidence=self.confidence,
            first_seen=sighted_at,
            last_seen=sighted_at,
            where_sighted_refs=[sighter_id],
            # Use a dummy indicator since this field is required:
            sighting_of_ref=self.DUMMY_INDICATOR_ID,
            custom_properties={"x_opencti_sighting_of_ref": observable_id},
            external_references=[
                stix2.ExternalReference(
                    source_name="Wazuh",
                    description=f"Wazuh alert ID {alert['_id']}/{s['id']}: {s['rule']['description']}",
                    url=urljoin(
                        self.app_url,
                        f'app/discover#/context/wazuh-alerts-*/{alert["_id"]}?_a=(columns:!(_source),filters:!())',
                    ),
                )
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

    def start(self):
        self.helper.metric.state("idle")
        self.helper.listen(self._process_message)


import sys
import time

if __name__ == "__main__":
    try:
        wazuh = WazuhConnector()
        wazuh.start()
    except Exception as e:
        print(e)
        time.sleep(2)
        sys.exit(0)
