#!/bin/python3
import os
import sys
import pytest
import datetime
from pydantic import AnyHttpUrl

sys.path.insert(0, os.path.abspath("../../src"))
from wazuh.enrich_config import EnrichmentConfig, FilenameBehaviour
from wazuh.opensearch_dsl import SortOrder
from wazuh.config import Config
from wazuh.search_config import DirSearchOption, FileSearchOption, ProcessSearchOption
from wazuh.connector_config import ConnectorType, LogLevel, SupportedEntity


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("OPENCTI_URL", "http://opencti:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "admintoken")
    monkeypatch.setenv("CONNECTOR_ID", "81f9d582-2b4e-45f1-98b6-f33492d66b6e")
    monkeypatch.setenv("CONNECTOR_NAME", "Wazuh")
    monkeypatch.setenv(
        "CONNECTOR_SCOPE",
        "Artifact, Directory,Domain-Name,Email-Addr,Hostname,IPv4-Addr,IPv6-Addr,Mac-Addr,Network-Traffic,Process,Software,StixFile,Url,User-Account,User-Agent,Windows-Registry-Key,Windows-Registry-Value-Type,Vulnerability, Indicator",
    )
    monkeypatch.setenv("CONNECTOR_AUTO", "true")
    monkeypatch.setenv("CONNECTOR_CONFIDENCE_LEVEL", "100")
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "debug")
    monkeypatch.setenv("CONNECTOR_EXPOSE_METRICS", "true")
    monkeypatch.setenv("WAZUH_APP_URL", "https://wazuh.example.org")
    monkeypatch.setenv("WAZUH_OPENSEARCH_URL", "https://wazuh.example.org:9200")
    monkeypatch.setenv("WAZUH_OPENSEARCH_USERNAME", "cti_connector")
    monkeypatch.setenv("WAZUH_OPENSEARCH_PASSWORD", "os_password")
    monkeypatch.setenv("WAZUH_OPENSEARCH_INDEX", "wazuh-alerts-*")
    monkeypatch.setenv("WAZUH_OPENSEARCH_VERIFY_TLS", "false")
    monkeypatch.setenv("WAZUH_OPENSEARCH_SEARCH_AFTER", "3 months ago")
    monkeypatch.setenv("WAZUH_API_ENABLED", "false")
    monkeypatch.setenv("WAZUH_API_URL", "https://wazuh.example.org:55000")
    monkeypatch.setenv("WAZUH_API_USERNAME", "api_ro")
    monkeypatch.setenv("WAZUH_API_PASSWORD", "w_password")
    monkeypatch.setenv("WAZUH_MAX_HITS", "50")
    monkeypatch.setenv("WAZUH_SYSTEM_NAME", "Wazuh SIEM")
    monkeypatch.setenv("WAZUH_AUTHOR_NAME", "Wazuh")
    monkeypatch.setenv("WAZUH_ORDER_BY_RULE_LEVEL", "true")
    monkeypatch.setenv("WAZUH_ALERTS_AS_NOTES", "true")
    monkeypatch.setenv("WAZUH_SEARCH_LOOKUP_AGENT_IP", "false")
    monkeypatch.setenv("WAZUH_SEARCH_LOOKUP_AGENT_NAME", "true")
    monkeypatch.setenv("WAZUH_SEARCH_IGNORE_PRIVATE_ADDRS", "false")
    monkeypatch.setenv("WAZUH_CREATE_OBSERVABLE_SIGHTINGS", "true")
    monkeypatch.setenv("WAZUH_MAX_TLP", "TLP:RED")
    monkeypatch.setenv("WAZUH_TLP", "TLP:AMBER")
    monkeypatch.setenv("WAZUH_SIGHTING_MAX_EXTREFS", "10")
    monkeypatch.setenv("WAZUH_SIGHTING_MAX_EXTREFS_PER_ALERT_RULE", "2")
    monkeypatch.setenv("WAZUH_SIGHTING_MAX_NOTES", "10")
    monkeypatch.setenv("WAZUH_SIGHTING_MAX_NOTES_PER_ALERT_RULE", "2")
    monkeypatch.setenv("WAZUH_INCIDENT_REQUIRE_INDICATOR", "false")
    monkeypatch.setenv("WAZUH_INCIDENT_CREATE_MODE", "per_sighting")
    monkeypatch.setenv("WAZUH_ENRICH_TYPES", "all")
    monkeypatch.setenv("WAZUH_ENRICH_AGENT", "true")
    monkeypatch.setenv("WAZUH_ENRICH_LABEL_ADD_LIST", "wazuh_ignore")
    monkeypatch.setenv("WAZUH_CREATE_AGENT_IP_OBSERVABLE", "true")
    monkeypatch.setenv("WAZUH_CREATE_AGENT_HOSTNAME_OBSERVABLE", "false")
    monkeypatch.setenv("WAZUH_ENRICH_FILENAME_BEHAVIOUR", "create-dir,remove-path")
    monkeypatch.setenv("WAZUH_IGNORE_OWN_ENTITIES", "false")
    monkeypatch.setenv("WAZUH_LABEL_IGNORE_LIST", "hygiene,wazuh_ignore,foobar")
    monkeypatch.setenv("WAZUH_CREATE_INCIDENT_RESPONSE", "true")

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
        "connector": {
            "auto": True,
            "id": "81f9d582-2b4e-45f1-98b6-f33492d66b6e",
            "log_level": LogLevel.Debug,
            "name": "Wazuh",
            "scope": {
                SupportedEntity.Artifact,
                SupportedEntity.Directory,
                SupportedEntity.DomainName,
                SupportedEntity.EMailAddr,
                SupportedEntity.Hostname,
                SupportedEntity.IPv4Addr,
                SupportedEntity.IPv6Addr,
                SupportedEntity.MAC,
                SupportedEntity.NetworkTraffic,
                SupportedEntity.Process,
                SupportedEntity.Software,
                SupportedEntity.StixFile,
                SupportedEntity.URL,
                SupportedEntity.UserAccount,
                SupportedEntity.UserAgent,
                SupportedEntity.WindowsRegistryKey,
                SupportedEntity.WindowsRegistryValueType,
                SupportedEntity.Vulnerability,
                SupportedEntity.Indicator,
            },
            "type": ConnectorType.InternalEnrichment,
        },
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
        "search": {
            "lookup_agent_ip": False,
            "lookup_agent_name": True,
            "ignore_private_addrs": False,
            "lookup_mac_variants": True,
            "lookup_hostnames_in_cmd_line": False,
            "lookup_url_without_host": False,
            "lookup_url_ignore_trailing_slash": False,
            "filesearch_options": {
                FileSearchOption.SearchSize,
                FileSearchOption.SearchAdditionalFilenames,
                FileSearchOption.IncludeParentDirRef,
                FileSearchOption.IncludeRegValues,
                FileSearchOption.SearchFilenameOnly,
                FileSearchOption.AllowRegexp,
                FileSearchOption.CaseInsensitive,
            },
            "dirsearch_options": {
                DirSearchOption.MatchSubdirs,
                DirSearchOption.SearchFilenames,
                DirSearchOption.AllowRegexp,
                DirSearchOption.IgnoreTrailingSlash,
                DirSearchOption.CaseInsensitive,
            },
            "procsearch_options": {ProcessSearchOption.CaseInsensitive},
        },
        "hits_abort_limit": 1000,
        "ignore_own_entities": False,
        "ignore_revoked_indicators": True,
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
        "opencti": {
            "ssl_verify": False,
            "token": "admintoken",
            "url": AnyHttpUrl("http://opencti:8080/"),
        },
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
            "search_after": datetime.timedelta(days=90),
            "url": AnyHttpUrl("https://wazuh.example.org:9200/"),
            "username": "cti_connector",
            "verify_tls": False,
        },
        "require_indicator_detection": False,
        "require_indicator_for_incidents": True,
        "system_name": "Wazuh SIEM",
        "tlps": {
            "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37",
        },
    }

    assert config.model_dump(exclude_none=True) == expected
