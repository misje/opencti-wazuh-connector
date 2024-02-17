import json
import stix2

# from stix2.v21.vocab import ENCRYPTION_ALGORITHM_MIME_TYPE_INDICATED
import yaml
import urllib3
import requests
from pathlib import Path
from pycti import (
    Identity,
    Note,
    ObservedData,
    OpenCTIConnectorHelper,
    StixSightingRelationship,
    get_config_variable,
    AttackPattern,
    StixCoreRelationship,
)
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from urllib.parse import urljoin
from typing import Final
from hashlib import sha256

# TODO:
#  metrics: run_coiunt, bundle_send, record_send, error_count, client_error_count
#  state: idle, running, stopped
#
# Populate agents using agent metadata?
# Helper functions for building stix objects
# SETTING: search_from limit search back in time


def has(obj, spec, value=None):
    if not spec:
        return obj == value if value is not None else True
    try:
        key, *rest = spec
        return has(obj[key], rest, value=value)
    except (KeyError, TypeError):
        return False


def filter_alerts(alerts):
    return [
        alert for alert in alerts if not has(alert, ["data", "integration"], "opencti")
    ]


class OpenSearchClient:
    def __init__(
        self,
        *,
        helper: OpenCTIConnectorHelper,
        url: str,
        username: str,
        password: str,
        limit: int,
        index: str,
    ) -> None:
        self.url = url
        self.username = username
        self.password = password
        self.index = index
        self.limit = limit
        self.helper = helper

        self.helper.connector_logger.info(f"[Wazuh] URL: {self.url}")

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _query(self, endpoint, query):
        adapter = HTTPAdapter(
            max_retries=Retry(
                total=3,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "OPTIONS"],
            )
        )
        http = requests.Session()
        http.auth = (self.username, self.password)
        http.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        http.mount(self.url, adapter)
        # TODO:
        http.verify = False

        try:
            response = http.get(
                urljoin(self.url, endpoint),
                json=query,
            )
            response.raise_for_status()

            try:
                # TODO: reponse now guaranteed to be 200?
                self.helper.connector_logger.debug(
                    f"[Wazuh] Query response status: {response.status_code}"
                )
                # self.helper.connector_logger.debug(
                #    f"[Wazuh] Query response: {response.json()}"
                # )
                return response.json()
            except json.JSONDecodeError as e:
                self.helper.connector_logger.error(
                    f"[Wazuh] Query: Failed to parse response: {response.text}: {e}"
                )
                self.helper.metric.inc("client_error_count")
                return None

        except requests.exceptions.HTTPError as e:
            self.helper.connector_logger.error(f"[Wazuh] Query: HTTP error: {e}")
            self.helper.metric.inc("client_error_count")
        except requests.exceptions.ConnectionError as e:
            self.helper.connector_logger.error(f"[Wazuh] Query: Connection error: {e}")
            self.helper.metric.inc("client_error_count")
        except requests.exceptions.Timeout as e:
            self.helper.connector_logger.error(f"[Wazuh] Query: Timed out: {e}")
            self.helper.metric.inc("client_error_count")
        except requests.exceptions.URLRequired:
            self.helper.connector_logger.error(
                "f[Wazuh] Query: URL not set or invalid: {self.url}"
            )
            self.helper.metric.inc("client_error_count")
        except Exception as e:
            self.helper.connector_logger.error(f"[Wazuh] Query: Unknown error: {e}")
            self.helper.metric.inc("client_error_count")

    def _search(self, query: dict):
        query = {
            "query": query,
            "size": self.limit,
            "sort": [{"timestamp": {"order": "desc"}}],
        }

        r = self._query(f"{self.index}/_search", query=query)
        if not r:
            return None
        try:
            if r["timed_out"]:
                self.helper.connector_logger.warning(
                    "[Wazuh] OpenSearch: Query timed out"
                )
                self.helper.connector_logger.debug(
                    "[Wazuh] OpenSearh: Searched {}/{} shards, {} skipped, {} failed".format(
                        r["_shards"]["successful"],
                        r["_shards"]["total"],
                        r["_shards"]["skipped"],
                        r["_shards"]["failed"],
                    )
                )
            if r["hits"]["total"]["value"] > self.limit:
                self.helper.connector_logger.warning(
                    "[Wazuh] Processing only {} of {} hits (hint: increase 'max_hits')".format(
                        self.limit, r["hits"]["total"]["value"]
                    )
                )

            return [hit for hit in r["hits"]["hits"]]

        except (IndexError, KeyError):
            self.helper.connector_logger.error(
                "[Wazuh]: Failed to parse result: Unexpected JSON structure"
            )
            self.helper.metric.inc("client_error_count")

    def search_must(self, terms: dict):
        return self._search(
            {
                "bool": {
                    "must": [{"match": {key: value}} for key, value in terms.items()]
                }
            }
        )

    def search_multi(
        self,
        *,
        fields: list[str],
        value: str,
    ):
        return self._search(
            {
                "multi_match": {
                    "query": value,
                    "fields": fields,
                }
            }
        )


class WazuhConnector:
    def __init__(self):
        config_file_path = Path(__file__).parent.parent.resolve() / "config.yml"
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if config_file_path.is_file()
            else {}
        )
        self.DUMMY_INDICATOR_ID: Final[
            str
        ] = "indicator--220d5816-3786-5421-a6d3-fb149a0df54e"  # "indicator--c1034564-a9fb-429b-a1c1-c80116cc8e1e"
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
            "WAZUH_SYSTEM_NAME", ["wazuh", "system_name"], config, default="Wazuh"
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
        )

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

        # TODO: Loop the matching below for each observable in indicator:
        # if entity['entity_type'] == 'Indicator' and 'observables' in entity and entity['observables']:

        hits = []
        match entity["entity_type"]:
            # TODO: Indicators: look up addresses, domain names and hashes
            case "Indicator":
                self.helper.log_debug(f"Indicator: {entity}")
            case "StixFile" | "Artifact":
                hits = self.client.search_multi(
                    fields=["*sha256*"], value=stix_entity["hashes"]["SHA-256"]
                )
            # TODO: add a setting WAZUH_SEARCH_AGENT_IP (should search agent.ip or not?
            case "IPv4-Addr" | "IPv6-Addr":
                hits = self.client.search_multi(
                    fields=[
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
                        "*.callerIp",
                        "*.ipAddress",
                        "data.win.eventdata.queryName",
                    ],
                    value=entity["observable_value"],
                )
            case "Domain-Name" | "Hostname":
                hits = self.client.search_multi(
                    fields=["data.win.eventdata.queryName", "*.hostname"],
                    value=entity["observable_value"],
                )
            case "Url":
                hits = self.client.search_multi(
                    fields=["*.url"],
                    value=entity["observable_value"],
                )
            case "Directory":
                hits = self.client.search_multi(
                    fields=["*.path"],
                    value=stix_entity["path"],
                )
            case "Windows-Registry-Key":
                self.helper.log_debug(stix_entity)
                hits = self.client.search_multi(
                    fields=["data.win.eventdata.targetObject", "syscheck.path"],
                    value=stix_entity["key"],
                )
            case "Windows-Registry-Value-Type":
                if stix_entity["data_type"] == "REG_SZ":
                    hits = self.client.search_multi(
                        fields=["syscheck.sha256_after"],
                        value=sha256(stix_entity["data"].encode("utf-8")).hexdigest(),
                    )
                else:
                    self.helper.connector_logger.info(
                        f'''Ignoring unsupported registry value type "{stix_entity['data_type']}"'''
                    )
            # TODO: use wazuh API?:
            # case "Process":
            # case "Software":
            case "Vulnerability":
                hits = self.client.search_must(
                    {
                        "data.vulnerability.cve": stix_entity["name"],
                        "data.vulnerability.status": "Active",
                    }
                )
            case "User-Account":
                hits = self.client.search_multi(
                    fields=[
                        "*.dstuser",
                        "*.srcuser",
                        "*.user",
                    ],
                    value=stix_entity["account_login"],
                )
            case _:
                raise ValueError(
                    f'{entity["entity_type"]} is not a supported entity type'
                )

        if hits is None:
            self.helper.metric.state("idle")
            return "Failed to query Wazuh API"

        hits = filter_alerts(hits)
        if not hits:
            self.helper.metric.state("idle")
            # FIXME: make show up as error in connector view:
            return "No hits found"

        sighter = self.siem_system
        bundle = [self.author]
        agents = {}
        for hit in hits:
            try:
                s = hit["_source"]
                if has(s, ["agent", "name"]) and self.agents_as_systems:
                    agents[s["agent"]["name"]] = sighter = self.create_agent_stix(hit)

                sighted_at = s["@timestamp"]
                sighting = self.create_sighting_stix(
                    sighter_id=sighter.id,
                    observable_id=entity["standard_id"],
                    alert=hit,
                )

                self.helper.connector_logger.debug(
                    f"Creating sighting in system {sighter.name} for alert at {sighted_at}"
                )
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
                self.helper.metric.inc("client_error_count")

        # Only add Wazyh SIEM system if it is referenced:
        if not agents:
            bundle += [self.siem_system]

        bundle += list(agents.values())
        sent_count = len(
            self.helper.send_stix2_bundle(
                self.helper.stix2_create_bundle(bundle), update=True
            )
        )
        return f"Sent {sent_count} STIX bundle(s) for worker import"

    def create_agent_stix(self, alert):
        s = alert["_source"]
        name = s["agent"]["name"]
        return stix2.Identity(
            id=Identity.generate_id(name, "system"),
            created_by_ref=self.author["id"],
            confidence=self.confidence,
            name=name,
            identity_class="system",
            description=f"Wazuh agent ID {s['agent']['id']}",
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
            created_by_ref=self.author["id"],
            confidence=self.confidence,
            abstract=f"""Wazuh alert "{s['rule']['description']}" (index {alert["_index"]}) for sighting at {sighted_at}""",
            content=f"```\n{alert_json}\n" "",
            object_refs=sighting_id,
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
