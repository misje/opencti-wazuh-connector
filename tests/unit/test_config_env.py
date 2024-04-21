#!/bin/python3
import os
import sys
import pytest
from pydantic import AnyHttpUrl

sys.path.insert(0, os.path.abspath("../../src"))
from wazuh.opensearch_config import OpenSearchConfig
from wazuh.enrich_config import EnrichmentConfig, FilenameBehaviour
from wazuh.opensearch_dsl import SortOrder
from wazuh.config import Config


@pytest.fixture(scope="session", autouse=True)
def set_env():
    os.environ["OPENCTI_URL"] = "http://opencti:8080"
    os.environ["OPENCTI_TOKEN"] = "admintoken"
    os.environ["CONNECTOR_ID"] = "81f9d582-2b4e-45f1-98b6-f33492d66b6e"
    os.environ["CONNECTOR_NAME"] = "Wazuh"
    os.environ[
        "CONNECTOR_SCOPE"
    ] = "Artifact,Directory,Domain-Name,Email-Addr,Hostname,IPv4-Addr,IPv6-Addr,Mac-Addr,Network-Traffic,Process,Software,StixFile,Url,User-Account,Windows-Registry-Key,Windows-Registry-Value-Type,Vulnerability"
    os.environ["CONNECTOR_AUTO"] = "true"
    os.environ["CONNECTOR_CONFIDENCE_LEVEL"] = "100"
    os.environ["CONNECTOR_LOG_LEVEL"] = "debug"
    os.environ["CONNECTOR_EXPOSE_METRICS"] = "true"
    os.environ["WAZUH_APP_URL"] = "https://wazuh.example.org"
    os.environ["WAZUH_OPENSEARCH_URL"] = "https://wazuh.example.org:9200"
    os.environ["WAZUH_OPENSEARCH_USERNAME"] = "cti_connector"
    os.environ["WAZUH_OPENSEARCH_PASSWORD"] = "os_password"
    os.environ["WAZUH_OPENSEARCH_INDEX"] = "wazuh-alerts-*"
    os.environ["WAZUH_OPENSEARCH_VERIFY_TLS"] = "false"
    # os.environ["WAZUH_OPENSEARCH_SEARCH_AFTER"] = "3 months ago"
    os.environ["WAZUH_API_ENABLED"] = "false"
    os.environ["WAZUH_API_URL"] = "https://wazuh.example.org:55000"
    os.environ["WAZUH_API_USERNAME"] = "api_ro"
    os.environ["WAZUH_API_PASSWORD"] = "w_password"
    os.environ["WAZUH_MAX_HITS"] = "50"
    os.environ['"WAZUH_SYSTEM_NAME'] = "Wazuh SIEM"
    os.environ["WAZUH_AUTHOR_NAME"] = "Wazuh"
    os.environ["WAZUH_ORDER_BY_RULE_LEVEL"] = "true"
    os.environ["WAZUH_ALERTS_AS_NOTES"] = "true"
    os.environ["WAZUH_SEARCH_AGENT_IP"] = "false"
    os.environ["WAZUH_SEARCH_AGENT_NAME"] = "false"
    os.environ["WAZUH_CREATE_OBSERVABLE_SIGHTINGS"] = "true"
    os.environ["WAZUH_MAX_TLP"] = "TLP:RED"
    os.environ["WAZUH_TLP"] = "TLP:AMBER"
    os.environ["WAZUH_SIGHTING_MAX_EXTREFS"] = "10"
    os.environ["WAZUH_SIGHTING_MAX_EXTREFS_PER_ALERT_RULE"] = "2"
    os.environ["WAZUH_SIGHTING_MAX_NOTES"] = "10"
    os.environ["WAZUH_SIGHTING_MAX_NOTES_PER_ALERT_RULE"] = "2"
    os.environ["WAZUH_INCIDENT_REQUIRE_INDICATOR"] = "false"
    os.environ["WAZUH_INCIDENT_CREATE_MODE"] = "per_sighting"
    # WAZUH_INCIDENT_CREATE_THRESHOLD=medium # [low, medium, high, critical] or [0–15]
    os.environ["WAZUH_ENRICH_TYPES"] = "all"
    os.environ["WAZUH_ENRICH_AGENT"] = "true"
    os.environ["WAZUH_ENRICH_LABEL_ADD_LIST"] = "wazuh_ignore"
    os.environ["WAZUH_CREATE_AGENT_IP_OBSERVABLE"] = "true"
    os.environ["WAZUH_CREATE_AGENT_HOSTNAME_OBSERVABLE"] = "false"
    os.environ["WAZUH_ENRICH_FILENAME_BEHAVIOUR"] = "create-dir,remove-path"
    os.environ["WAZUH_IGNORE_OWN_ENTITIES"] = "false"
    os.environ["WAZUH_LABEL_IGNORE_LIST"] = "hygiene,wazuh_ignore,foobar"
    os.environ["WAZUH_CREATE_INCIDENT_RESPONSE"] = "true"


def test_config_from_env():
    config = Config.model_validate({})
    expected = {
        "agents_as_systems": True,
        "api": {
            "enabled": False,
            "password": "w_password",
            "url": AnyHttpUrl("https://wazuh.example.org:55000/"),
            "username": "api_ro",
            "verify_tls": True,
        },
        "app_url": AnyHttpUrl("https://wazuh.example.org/"),
        "author_name": "Wazuh",
        "bundle_abort_limit": 500,
        "create_agent_hostname_observable": False,
        "create_agent_ip_observable": True,
        "create_incident": Config.IncidentCreateMode.PerSighting,
        "create_incident_response": True,
        "create_incident_summary": True,
        "create_incident_threshold": 1,
        "create_obs_sightings": True,
        "create_sighting_summary": True,
        "enrich": {
            "filename_behaviour": {
                FilenameBehaviour.RemovePath,
                FilenameBehaviour.CreateDir,
            },
            "types": {
                EnrichmentConfig.EntityType.MAC,
                EnrichmentConfig.EntityType.RegistryKey,
                EnrichmentConfig.EntityType.Process,
                EnrichmentConfig.EntityType.NetworkTraffic,
                EnrichmentConfig.EntityType.Tool,
                EnrichmentConfig.EntityType.Domain,
                EnrichmentConfig.EntityType.URL,
                EnrichmentConfig.EntityType.UserAgent,
                EnrichmentConfig.EntityType.EMailAddr,
                EnrichmentConfig.EntityType.File,
                EnrichmentConfig.EntityType.IPv6Address,
                EnrichmentConfig.EntityType.IPv4Address,
                EnrichmentConfig.EntityType.AttackPattern,
                EnrichmentConfig.EntityType.Account,
                EnrichmentConfig.EntityType.Directory,
                EnrichmentConfig.EntityType.Software,
                EnrichmentConfig.EntityType.Vulnerability,
            },
        },
        "enrich_agent": True,
        "enrich_labels": {
            "wazuh_ignore",
        },
        "hits_abort_limit": 1000,
        "ignore_own_entities": False,
        "ignore_private_addrs": True,
        "label_ignore_list": {
            "foobar",
            "hygiene",
            "wazuh_ignore",
        },
        "max_extrefs": 10,
        "max_extrefs_per_alert_rule": 2,
        "max_notes": 10,
        "max_notes_per_alert_rule": 2,
        "max_tlp": "TLP:RED",
        "opensearch": {
            "exclude_match": [
                {
                    "match": {
                        "data.integration": "opencti",
                    },
                },
            ],
            "filter": [],
            "include_match": [],
            "index": "wazuh-alerts-*",
            "limit": 50,
            "order_by": [
                {
                    "timestamp": {
                        "order": SortOrder.Desc,
                    },
                },
            ],
            "password": "os_password",
            "url": AnyHttpUrl("https://wazuh.example.org:9200/"),
            "username": "cti_connector",
            "verify_tls": False,
        },
        "require_indicator_for_incidents": True,
        "search_agent_ip": False,
        "search_agent_name": False,
        "system_name": "Wazuh SIEM",
        "tlps": {
            "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37",
        },
    }

    assert config.model_dump(exclude_none=True) == expected
