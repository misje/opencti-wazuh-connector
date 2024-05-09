#!/bin/python3
import os
import sys
import pytest
from pydantic import ValidationError

sys.path.insert(0, os.path.abspath("../../src"))
from wazuh.connector_config import ConnectorConfig, ConnectorType, SupportedEntity


def test_missing_throws():
    with pytest.raises(ValidationError):
        ConnectorConfig()


def test_nomissing_nothrow():
    ConnectorConfig(id="foo")


def test_type_from_env(monkeypatch):
    monkeypatch.setenv("CONNECTOR_TYPE", "internal_enrichment")
    assert ConnectorConfig(id="foo").type == ConnectorType.InternalEnrichment


def test_scope_from_env(monkeypatch):
    E = SupportedEntity
    monkeypatch.setenv(
        "CONNECTOR_SCOPE", "IPv4-Addr, ipv6addr, Software,URL, IndicATOR"
    )
    assert ConnectorConfig(id="foo").scope == {
        E.IPv4Addr,
        E.IPv6Addr,
        E.Software,
        E.URL,
        E.Indicator,
    }
