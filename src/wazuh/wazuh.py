import json
import stix2
import ipaddress
import logging
import time
from .config import Config
from .opensearch import OpenSearchClient
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
)
from typing import Any, Final
from datetime import datetime
from urllib.parse import urljoin
from functools import reduce
from .utils import (
    cvss3_severity_to_score,
    datetime_string,
    field_or_default,
    has,
    lists_or_empty,
    rule_level_to_severity,
    priority_from_severity,
    max_severity,
    common_prefix_string,
    search_field,
    search_fields,
    search_in_object_multi,
    truncate_string,
)
from .stix_helper import (
    # SCO,
    # SDO,
    # SRO,
    # StandardID,
    DUMMY_INDICATOR_ID,
    remove_unref_objs,
    tlp_allowed,
    entity_values,
    entity_name_value,
    incident_entity_relation_type,
    StixHelper,
)
from .sightings import SightingsCollector
from .search import AlertSearcher
from .enrich import Enricher


log = logging.getLogger(__name__)


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


def alert_md_table(alert: dict, additional_rows: list[tuple[str, str]] | None = None):
    """
    Create a markdown table with key Wazuh alert information

    Any additional rows can be appended to the table using additional_rows.
    """
    s = alert["_source"]
    if additional_rows is None:
        additional_rows = []

    return (
        "|Key|Value|\n"
        "|---|-----|\n"
        f"|Rule ID|{s['rule']['id']}|\n"
        f"|Rule desc.|{s['rule']['description']}|\n"
        f"|Rule level|{s['rule']['level']}|\n"
        f"|Alert ID|{alert['_id']}/{s['id']}|\n"
    ) + "".join(f"|{key}|{value}|\n" for key, value in additional_rows)


def vulnerability_active(sightings: SightingsCollector) -> bool:
    """
    Whether the vulnerability found is no longer present in the systems it was
    sighted
    """
    # Create a dict with sighter (system ID) as keys, and a dict with alert
    # rule ID and "last seen" timestamps:
    last_seen = {
        sighter: {
            rule_id: max((a["_source"]["@timestamp"] for a in alerts))
            for rule_id, alerts in meta.alerts.items()
            if alerts
        }
        for sighter, meta in sightings.collated().items()
    }
    # Create a map of when vulnerabilities were last seen per system:
    active = {
        sighter: timestamp
        for sighter, rs in last_seen.items()
        for rule_id, timestamp in rs.items()
        if rule_id in ("23503", "23504", "23505", "23506")
    }
    # Create a map of when vulnerabilities were last resolved (a patch was
    # installed, the program was removed etc.) per system:
    resolved = {
        sighter: timestamp
        for sighter, rs in last_seen.items()
        for rule_id, timestamp in rs.items()
        if rule_id == "23502"
    }
    # List systems with vulnerabilities still installed:
    sighters_with_unresolved = {
        sighter
        for sighter in active.keys()
        if sighter not in resolved or resolved[sighter] < active[sighter]
    }
    return bool(sighters_with_unresolved)


def cvss3_from_alert(alerts: list[dict], cve: str) -> dict[str, str | float]:
    """
    Extract CVSS3 metadata from vulnerability alerts

    Examples:

    >>> cvss3_from_alert([{'_source': {'data': {'vulnerability': {'cve': 'CVE-2020-1234', 'severity': 'high'}}}}, {'_source': {'data': {'vulnerability': {'cve': 'CVE-2020-1234', 'severity': '', 'cvss': {'cvss3': {'base_score': 9.9}}}}}}], 'CVE-2020-1234')
    {'data.vulnerability.severity': 'high', 'data.vulnerability.cvss.cvss3.base_score': 9.9}
    """
    return {
        field: value
        for alert in alerts
        if search_field(alert["_source"], "data.vulnerability.cve", regex=cve)
        for field, value in search_fields(
            alert["_source"],
            [
                "data.vulnerability.cvss.cvss3.base_score",
                "data.vulnerability.severity",
            ],
        ).items()
        if value
    }


def cvss3_score_from_alert(alerts: list[dict], cve: str, default: float) -> float:
    result = cvss3_from_alert(alerts, cve).get(
        "data.vulnerability.cvss.cvss3.base_score"
    )
    log.debug(f"Looking up CVSS3 base score from alerts: {result}")
    return float(result) if result is not None else default


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

    def __init__(self, config: Config):
        self.CONNECTOR_VERSION: Final[str] = "0.3.0"

        self.conf = config
        self.helper = OpenCTIConnectorHelper(
            # Give the helper a dict with only the relevant members:
            {
                k: v
                for k, v in config.model_dump(mode="json").items()
                if k in ("opencti", "connector")
            },
            True,
        )

        self.stix_common_attrs = {
            "object_marking_refs": self.conf.tlps,
            # The connector should not need to set the confidence explicltly,
            # but due to #6835(?), this doesn't seem to work for sightings.
            # This confidence will be lowered to that of the connector's user
            # or group memberships:
            "confidence": 100,
        }
        # Add moe useful meta to author?
        self.author = stix2.Identity(
            id=Identity.generate_id("Wazuh", "system"),
            **self.stix_common_attrs,
            name=self.conf.author_name,
            identity_class="organization",
            description="Wazuh",
        )
        self.stix_common_attrs["created_by_ref"] = self.author["id"]
        self.stix = StixHelper(
            common_properties=self.stix_common_attrs,
            sco_labels=list(self.conf.enrich_labels),
            filename_behaviour=self.conf.enrich.filename_behaviour,
        )
        self.enricher = Enricher(
            helper=self.helper,
            stix=self.stix,
            config=self.conf.enrich,
        )
        self.siem_system = stix2.Identity(
            id=Identity.generate_id(self.conf.system_name, "system"),
            **self.stix_common_attrs,
            name=self.conf.system_name,
            identity_class="system",
        )
        self.app_url = str(self.conf.app_url)
        self.alert_searcher = AlertSearcher(
            helper=self.helper,
            opensearch=OpenSearchClient(config=self.conf.opensearch),
            config=self.conf.search,
        )

    def start(self):
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
            log.info(
                "Waiting a little while for indicator 'based-on' relationships to be ingested before processing"
            )
            time.sleep(0.1)
            ind = self.helper.api.indicator.read(id=data["entity_id"])
            ind_obs = ind["observables"] if ind and "observables" in ind else []
            # TODO: In some distant feature, with a STIX shifter implementation
            # for Wazuh, look up the STIX pattern in the indicator and use that
            # in a search (#9).
            # TODO: alternatively, add OpenSearch DSL as a custom pattern_type_ov and use something like mitre/stix2patterns_translator to convert int o elastic_query
            if not ind_obs:
                # FIXME: Not an error: just print as message. Throw a custom exception for messages?
                raise ValueError("Indicator is not based on any observables")
            elif (count := len(ind_obs)) > 1:
                log.warning(
                    f"Indicator is based on several observables; using the first out of {count}"
                )
            entity = self.helper.api.stix_cyber_observable.read(id=ind_obs[0]["id"])
        else:
            entity = self.helper.api.stix_cyber_observable.read(id=data["entity_id"])

        if entity is None:
            raise ValueError("Entity/observable not found")

        # Remove:
        log.debug(f"ENTITY: {entity}")

        if not tlp_allowed(entity, self.conf.max_tlp):  # type: ignore
            log.info(f"max tlp: {self.conf.max_tlp}")
            raise ValueError("Entity ignored because TLP not allowed")

        if (
            self.conf.ignore_own_entities
            and has(entity, ["createdBy", "standard_id"])
            and entity["createdBy"]["standard_id"] == self.author.id
        ):
            return f"Ignoring entity because it was created by {self.author.name}"

        # Figure out exactly what this does (change id format?);
        enrichment = self.helper.get_data_from_enrichment(
            data, entity["standard_id"], entity
        )
        stix_entity = enrichment["stix_entity"]
        # Remove:
        log.debug(f"STIX_ENTITY: {stix_entity}")

        obs_indicators = [
            ind for ind in self.entity_indicators(entity) if self.valid_indicator(ind)
        ]
        # Remove:
        log.debug(f"Indicators: {obs_indicators}")

        if self.conf.label_ignore_list:
            matching_labels = [
                label
                for label in self.conf.label_ignore_list
                if label in lists_or_empty(stix_entity, "labels", "x_opencti_labels")
            ]
            if matching_labels:
                return f"Ignoring entity because it has the following label(s): {', '.join(matching_labels)}"

        if (
            entity_type == "observable"
            and not obs_indicators
            and not self.conf.create_obs_sightings
        ):
            log.info(
                "Observable has no indicators and WAZUH_CREATE_OBSERVABLE_SIGHTINGS is false"
            )
            return "Observable has no indicators"

        result = self.alert_searcher.search(entity=entity, stix_entity=stix_entity)
        if result is None:
            # Even though the entity is supported (an exception is throuwn
            # otherwise), not all entities contains information that is
            # searchable in Wazuh. There may also not be enough information to
            # perform a search that is targeted enough. This is not an error:
            return f"{entity['entity_type']} has no queryable data"

        if result["_shards"]["failed"] > 0:
            for failure in result["_shards"]["failures"]:
                log.error(f"Query failure: {failure}")

        hits = result["hits"]["hits"]
        if not hits:
            return "No hits found"

        if (
            self.conf.hits_abort_limit is not None
            and (hit_count := result["hits"]["total"]["value"])
            > self.conf.hits_abort_limit
        ):
            raise ValueError(
                f"Too many hits ({hit_count} > {self.conf.hits_abort_limit}): aborting"
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
                if rule_id := s["rule"]["id"] in self.conf.rule_exclude_list:
                    log.info(
                        f"Ignoring alert rule id {rule_id} because it is in rule_exclude_list"
                    )
                    continue
                if (
                    has(s, ["agent", "id"])
                    and self.conf.agents_as_systems
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

        bundle += list(agents.values())
        bundle += self.relate_agents_to_siem(list(agents.values()), self.siem_system)

        if self.conf.create_agent_ip_observable:
            bundle += self.create_agent_addr_obs(alerts=hits)
        if self.conf.create_agent_hostname_observable:
            bundle += self.create_agent_hostname_obs(alerts=hits)

        # TODO: doesn't seem to work? Or bug in OpenCTI. Anyway, add STIXList
        # as type hint to bundle everywhere before continuing working on this:
        # bundle = add_incidents_to_note_refs(bundle)

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

        if (
            self.conf.require_indicator_for_incidents
            and entity_type == "observable"
            and not obs_indicators
        ):
            log.info(
                "Not creating incident because entity is an observable, an indicator is required and no indicators are found"
            )
        elif entity_type == "vulnerability" and (
            (score_threshold := self.conf.vulnerability_incident_cvss3_score_threshold)
            is None
            # First match against the actual CVSS3 score:
            or field_or_default(
                stix_entity,
                "x_opencti_cvss_base_score",
                cvss3_severity_to_score(
                    field_or_default(stix_entity, "x_opencti_cvss_base_severity", ""),
                    # As a last resort, try to get the score from searching alerts:
                    default=cvss3_score_from_alert(
                        alerts=hits, cve=stix_entity["name"], default=0.0
                    ),
                ),
            )
            < score_threshold
        ):
            log.info(
                "Not creating incident because entity is a vulnerability, and CVSS3 score is not present, threshold is not set, or threshold is not met"
            )
        elif (
            entity_type == "vulnerability"
            and self.conf.vulnerability_incident_active_only
            and not vulnerability_active(sightings_collector)
        ):
            log.info(
                "Not creating incident because entity is a vulnerability, vulnerability_incident_active_only is enabled, and the vulnerability is no longer present"
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
                + (sighting_ids if self.conf.create_sighting_summary else [])
                + [
                    obj.id
                    for obj in bundle
                    if self.conf.create_incident_summary and obj.type == "incident"
                ],
            )
        ]

        # NOTE: This must be the lastly created bundle, because it references
        # all other objects in the bundle list:
        if self.conf.create_incident_response and any(
            isinstance(obj, stix2.Incident) for obj in bundle
        ):
            bundle += self.create_incident_response_case(
                entity=entity, indicators=obs_indicators, result=result, bundle=bundle
            )

        if (
            self.conf.bundle_abort_limit is not None
            and (bundle_count := len(bundle)) > self.conf.bundle_abort_limit
        ):
            raise ValueError(
                f"Bundle is too large ({bundle_count} > {self.conf.bundle_abort_limit}): aborting"
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

    def valid_indicator(self, entity: dict) -> bool:
        if self.conf.require_indicator_detection and not field_or_default(
            entity, "detection", False
        ):
            log.info(f"Ignoring indicator {entity['name']} because detection is false")
            return False
        elif self.conf.ignore_revoked_indicators and field_or_default(
            entity, "revoked", False
        ):
            log.info(f"Ignoring indicator {entity['name']} because it is revoked")
            return False
        elif (threshold := self.conf.indicator_score_threshold) is not None and (
            score := field_or_default(entity, "x_opencti_score", 50)
        ) < threshold:
            log.info(
                f"Ignoring indicator {entity['name']} because its score is below the threshold: {score} < {threshold}"
            )
            return False

        return True

    def create_agent_stix(self, alert):
        s = alert["_source"]
        agent_id = s["agent"]["id"]
        name = s["agent"]["name"]
        return stix2.Identity(
            # id=Identity.generate_id(name, "system"),
            id=Identity.generate_id(agent_id, "system"),
            **self.stix_common_attrs,
            name=name,
            identity_class="system",
            description=self.generate_agent_md_tables(agent_id),
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
            # TODO: add description (alert rule IDs?) (#64)
            where_sighted_refs=[sighter_id],
            # Use a dummy indicator since this field is required:
            sighting_of_ref=DUMMY_INDICATOR_ID,
            custom_properties={"x_opencti_sighting_of_ref": metadata.observable_id},
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
            for alert in alerts[-self.conf.max_extrefs_per_alert_rule :]
            if (ext_ref_count := ext_ref_count + 1) <= self.conf.max_extrefs
        ]

    def create_alert_ext_ref(self, *, alert):
        return stix2.ExternalReference(
            source_name="Wazuh alert",
            description=alert_md_table(alert),
            url=urljoin(
                self.app_url,
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
            for i, alert in enumerate(alerts[-self.conf.max_notes_per_alert_rule :])
            for capped_at in (
                (i + 1, len(alerts), self.conf.max_notes_per_alert_rule)
                if len(alerts) > self.conf.max_notes_per_alert_rule
                else None,
            )
            if (note_count := note_count + 1) <= self.conf.max_notes
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
                    f"|{field}|{match_formatted}|\n"
                    for field, match in search_in_object_multi(
                        alert["_source"], *obs_values, exclude_fields=["full_log"]
                    ).items()
                    for match_formatted in (truncate_string(match.replace("\n", "")),)
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
        # TODO: link to query if a link to opensearch is possible (#68)
        content = (
            "## Wazuh enrichment summary\n"
            "\n\n"
            "|Key|Value|\n"
            "|---|---|\n"
            f"|Time|{run_time_string}|\n"
            f"|Duration|{result['took']} ms|\n"
            f"|Hits returned|{hits_returned}|\n"
            f"|Total hits|{total_hits}|\n"
            f"|Max hits|{self.conf.opensearch.limit}|\n"
            f"|**Dropped**|**{total_hits - hits_returned}**|\n"
            f"|Search since|{datetime_string(self.conf.opensearch.search_after)}|\n"
            f"|Include filter|{self.conf.opensearch.field_json('include_match')}|\n"
            f"|Exclude filter|{self.conf.opensearch.field_json('exclude_match')}|\n"
            f"|Connector v.|{self.CONNECTOR_VERSION}|\n"
            "\n"
            "### Alerts overview\n"
            "\n"
            "|Rule|Level|Count|Earliest|Latest|Description|\n"
            "|----|-----|-----|--------|------|-----------|\n"
        ) + "".join(
            f"[{rule_id}]({self.alert_rule_link(rule_id)})|{level}|{len(alerts)}{'+' if total_hits > hits_returned else ''}|{sightings_meta.first_seen(rule_id)}|{sightings_meta.last_seen(rule_id)}|{rule_desc}|\n"
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

    # TODO: Refactor – too long and repetitive!
    def create_incidents(
        self,
        *,
        entity: dict,
        obs_indicators: list[dict],
        result: dict,
        sightings_meta: SightingsCollector,
    ):
        def log_skipped_due_to_rule_level(level: int):
            log.info(
                f"Not creating incident because rule level below threshold: {level} < {self.conf.create_incident_threshold}"
            )
            return True

        def log_skipped_due_to_rule():
            log.info(
                "Not creating incident because rule ID is in incident_rule_exclude_list"
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
        # TODO: (#69(
        # severity = cvss3_score_to_severity(alert entity['entity_type'] == 'Vulnerability'
        match self.conf.create_incident:
            case Config.IncidentCreateMode.PerQuery:
                if (
                    level := sightings_meta.max_rule_level()
                ) < self.conf.create_incident_threshold:
                    log_skipped_due_to_rule_level(level)
                    return []
                if self.conf.incident_rule_exclude_list and all(
                    (
                        alert["_source"]["rule"]["id"]
                        in self.conf.incident_rule_exclude_list
                        for alert in sightings_meta.alerts()
                    )
                ):
                    log_skipped_due_to_rule()
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
                    source=self.conf.system_name,
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

            case Config.IncidentCreateMode.PerSighting:
                for sighter_id, meta in sightings.items():
                    if (
                        level := meta.max_rule_level
                    ) < self.conf.create_incident_threshold:
                        log_skipped_due_to_rule_level(level)
                        continue
                    if self.conf.incident_rule_exclude_list and all(
                        (
                            rule_id in self.conf.incident_rule_exclude_list
                            for rule_id in meta.alerts.keys()
                        )
                    ):
                        log_skipped_due_to_rule()
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
                        source=self.conf.system_name,
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

            case Config.IncidentCreateMode.PerAlertRule:
                for rule_id, meta in sightings_meta.alerts_by_rule_id_meta().items():
                    if (
                        self.conf.incident_rule_exclude_list
                        and rule_id in self.conf.incident_rule_exclude_list
                    ):
                        log_skipped_due_to_rule()
                        continue

                    # Alerts are grouped by ID and all have the same level, so just pick one:
                    alerts_level = meta["alerts"][0]["_source"]["rule"]["level"]
                    if alerts_level < self.conf.create_incident_threshold:
                        log_skipped_due_to_rule_level(alerts_level)
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
                        source=self.conf.system_name,
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

            case Config.IncidentCreateMode.PerAlert:
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
                            source=self.conf.system_name,
                        )
                        for alert in meta["alerts"]
                        for sighted_at in (alert["_source"]["@timestamp"],)
                        for rule_id in (alert["_source"]["rule"]["id"],)
                        for rule_desc in (alert["_source"]["rule"]["description"],)
                        for rule_level in (alert["_source"]["rule"]["level"],)
                        if (
                            rule_level >= self.conf.create_incident_threshold
                            # Just a hack to log some info:
                            or not log_skipped_due_to_rule_level(rule_level)
                        )
                        and not (
                            self.conf.incident_rule_exclude_list
                            and rule_id in self.conf.incident_rule_exclude_list
                            and log_skipped_due_to_rule()
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

                    # TODO: Implement (this solution doesn't work) (#73):
                    # bundle += [
                    #    enrichment
                    #    for filtered_alerts in [
                    #        alert
                    #        for alert in meta["alerts"]
                    #        if alert["_source"]["rule"]["level"]
                    #        >= self.conf.create_incident_threshold
                    #    ]
                    #    for pair in zip(incidents, filtered_alerts, strict=True)
                    #    for incident, alerts in (pair,)
                    #    for enrichment in self.enricher.enrich_incident(
                    #        incident=incident, alerts=alerts
                    #    )
                    # ]
            case Config.IncidentCreateMode.Never:
                return []

            case _:
                raise ValueError(
                    f'WAZUH_INCIDENT_CREATE_MODE "{self.conf.create_incident}" is invalid'
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
        self, *, entity: dict, indicators: list[dict], result: dict, bundle: list[Any]
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
        ind_info = "(no indicator)"
        if (ind_count := len(indicators)) > 1:
            ind_info = f"(part of {ind_count} indicators"
        elif ind_count == 1:
            ind_info = f"(part of the indicator {indicators[0]['name']})"
        # Remove any objects not referenced in relationships, as they will just
        # pollute the knowledge graph. These objects are typically nested
        # objects that the knowledge graph will not display anyway:
        refs = (
            [o.id for o in remove_unref_objs(bundle)]
            + [entity["standard_id"]]
            + [i["standard_id"] for i in indicators]
        )
        return (
            CustomObjectCaseIncident(
                id=CaseIncident.generate_id(name, timestamp),
                name=name,
                description=f"{entity_name_value(entity)} {ind_info} has been sighted {f'at least {sightings_count}' if hits_dropped else f'{sightings_count}'} times(s)",
                # NOTE: this may break if user changes case_severity_ov. Make customisable from setting(?)
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

        bundle = []
        earliest = min(alert["_source"]["@timestamp"] for alert in alerts)
        latest = max(alert["_source"]["@timestamp"] for alert in alerts)
        # STIX doesn't accept start == stop, so remove stop if they are the same:
        if latest == earliest:
            latest = None

        for agent in agents.values():
            SCO = (
                stix2.IPv4Address
                if isinstance(agent["ip"], ipaddress.IPv4Address)
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
                    "related-to",
                    agent["standard_id"],
                    hostname.id,  # pylint: disable=no-member
                ),
                **self.stix.common_properties,
                relationship_type="related-to",
                source_ref=agent["standard_id"],
                target_ref=hostname.id,  # pylint: disable=no-member
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

    def alert_rule_link(self, rule_id: str) -> str:
        return urljoin(
            self.app_url,  # type: ignore
            f"app/wazuh#/manager/?tab=rules&redirectRule={rule_id}",
        )
