#!/bin/python3
import os
import sys
import pytest
import random
import logging
from pycti import OpenCTIConnectorHelper
from pydantic import AnyHttpUrl

sys.path.insert(0, os.path.abspath("../../src"))
from wazuh.search import AlertSearcher
from wazuh.search_config import RegKeySearchOption, SearchConfig
from wazuh.opensearch import OpenSearchClient
from wazuh.opensearch_config import OpenSearchConfig
from wazuh.opensearch_dsl import Bool, MultiMatch, Regexp, Term
from test_common import osConf

fields = ["data.win.eventdata.targetObject", "syscheck.path"]


def dummy_func(monkeypatch):
    pass


def searcher(monkeypatch, **kwargs):
    monkeypatch.setattr(OpenCTIConnectorHelper, "__init__", dummy_func)
    return AlertSearcher(
        helper=OpenCTIConnectorHelper(),
        opensearch=OpenSearchClient(config=osConf()),
        config=SearchConfig(**kwargs),
    )


@pytest.fixture
def mock_search(monkeypatch):
    def return_input(*args, **kwargs):
        return {"must": args[1], **kwargs} if len(args) > 1 else kwargs

    monkeypatch.setattr(OpenSearchClient, "search", return_input)


def test_regkey_search_abs_no_abs(caplog, monkeypatch, mock_search):
    caplog.set_level(logging.INFO, logger="wazuh.search")
    s = searcher(
        monkeypatch,
        regkeysearch_options={
            RegKeySearchOption.RequireAbsPath,
        },
    )
    stix = {"key": "not\\absolute"}
    result = s.query_reg_key(stix_entity=stix)
    assert result is None
    messages = [record.msg for record in caplog.records]
    assert messages == ["Key is not absolute and RequireAbsPath is enabled"]


def test_regkey_search_no_abs_no_regexp(caplog, monkeypatch, mock_search):
    caplog.set_level(logging.INFO, logger="wazuh.search")
    s = searcher(
        monkeypatch,
        regkeysearch_options=set(),
    )
    stix = {"key": "not\\absolute"}
    result = s.query_reg_key(stix_entity=stix)
    assert result is None
    messages = [record.msg for record in caplog.records]
    assert messages == ["Key is not absolute and AllowRegexp is not enabled"]


def test_regkey_search_no_regexp(monkeypatch, mock_search):
    s = searcher(monkeypatch, regkeysearch_options=set())
    stix = {
        "key": "HKLM\\Security\\SAM\\Domains\\Builtin\\Aliases\\Members\\S-1-5-80-12345678-901234567-12345689-23456789\\foo\\bar",
    }
    result = s.query_reg_key(stix_entity=stix)
    assert result == {
        "should": [
            MultiMatch(
                query="HKLM\\Security\\SAM\\Domains\\Builtin\\Aliases\\Members\\S-1-5-80-12345678-901234567-12345689-23456789\\foo\\bar",
                fields=["data.win.eventdata.targetObject", "syscheck.path"],
            ),
            MultiMatch(
                query="HKLM\\\\Security\\\\SAM\\\\Domains\\\\Builtin\\\\Aliases\\\\Members\\\\S-1-5-80-12345678-901234567-12345689-23456789\\\\foo\\\\bar",
                fields=["data.win.eventdata.targetObject", "syscheck.path"],
            ),
        ]
    }


# TODO: test opt dep on AllowRegexp


def test_regkey_search_ignore_sid(monkeypatch, mock_search):
    s = searcher(
        monkeypatch,
        regkeysearch_options={
            RegKeySearchOption.IgnoreSID,
            RegKeySearchOption.AllowRegexp,
        },
    )
    stix = {
        "key": "HKLM\\Security\\SAM\\Domains\\Builtin\\Aliases\\Members\\S-1-5-80-12345678-901234567-12345689-23456789\\foo\\bar",
    }
    result = s.query_reg_key(stix_entity=stix)
    assert result == {
        "should": [
            Regexp(
                field="data.win.eventdata.targetObject",
                query="HKLM\\\\+Security\\\\+SAM\\\\+Domains\\\\+Builtin\\\\+Aliases\\\\+Members\\\\+S-1-[0-59]-[0-9]{2}-[0-9]{8,10}-[0-9]{8,10}-[0-9]{8,10}-[1-9][0-9]{3,9}\\\\+foo\\\\+bar",
                case_insensitive=False,
            ),
            Regexp(
                field="syscheck.path",
                query="HKLM\\\\+Security\\\\+SAM\\\\+Domains\\\\+Builtin\\\\+Aliases\\\\+Members\\\\+S-1-[0-59]-[0-9]{2}-[0-9]{8,10}-[0-9]{8,10}-[0-9]{8,10}-[1-9][0-9]{3,9}\\\\+foo\\\\+bar",
                case_insensitive=False,
            ),
        ]
    }


def test_regkey_search_ignore_sid_alias(monkeypatch, mock_search):
    s = searcher(
        monkeypatch,
        regkeysearch_options={
            RegKeySearchOption.SearchHiveAliases,
            RegKeySearchOption.IgnoreSID,
            RegKeySearchOption.AllowRegexp,
        },
    )
    stix = {
        "key": "HKLM\\Security\\SAM\\Domains\\Builtin\\Aliases\\Members\\S-1-5-80-12345678-901234567-12345689-23456789\\foo\\bar",
    }
    result = s.query_reg_key(stix_entity=stix)
    assert result == {
        "should": [
            Regexp(
                field="data.win.eventdata.targetObject",
                query="(HKEY_LOCAL_MACHINE|HKLM)\\\\+Security\\\\+SAM\\\\+Domains\\\\+Builtin\\\\+Aliases\\\\+Members\\\\+S-1-[0-59]-[0-9]{2}-[0-9]{8,10}-[0-9]{8,10}-[0-9]{8,10}-[1-9][0-9]{3,9}\\\\+foo\\\\+bar",
                case_insensitive=False,
            ),
            Regexp(
                field="syscheck.path",
                query="(HKEY_LOCAL_MACHINE|HKLM)\\\\+Security\\\\+SAM\\\\+Domains\\\\+Builtin\\\\+Aliases\\\\+Members\\\\+S-1-[0-59]-[0-9]{2}-[0-9]{8,10}-[0-9]{8,10}-[0-9]{8,10}-[1-9][0-9]{3,9}\\\\+foo\\\\+bar",
                case_insensitive=False,
            ),
        ]
    }


def test_regkey_search_ignore_sid_alias_subdirs_trailing(monkeypatch, mock_search):
    s = searcher(
        monkeypatch,
        regkeysearch_options={
            RegKeySearchOption.SearchHiveAliases,
            RegKeySearchOption.IgnoreSID,
            RegKeySearchOption.AllowRegexp,
            RegKeySearchOption.MatchSubdirs,
            RegKeySearchOption.IgnoreTrailingSlash,
        },
    )
    stix = {
        "key": "Security\\SAM\\Domains\\Builtin\\Aliases\\Members\\S-1-5-80-12345678-901234567-12345689-23456789\\foo\\bar",
    }
    result = s.query_reg_key(stix_entity=stix)
    assert result == {
        "should": [
            Regexp(
                field="data.win.eventdata.targetObject",
                query=".+\\\\+Security\\\\+SAM\\\\+Domains\\\\+Builtin\\\\+Aliases\\\\+Members\\\\+S-1-[0-59]-[0-9]{2}-[0-9]{8,10}-[0-9]{8,10}-[0-9]{8,10}-[1-9][0-9]{3,9}\\\\+foo\\\\+bar(\\\\+.*)?",
                case_insensitive=False,
            ),
            Regexp(
                field="syscheck.path",
                query=".+\\\\+Security\\\\+SAM\\\\+Domains\\\\+Builtin\\\\+Aliases\\\\+Members\\\\+S-1-[0-59]-[0-9]{2}-[0-9]{8,10}-[0-9]{8,10}-[0-9]{8,10}-[1-9][0-9]{3,9}\\\\+foo\\\\+bar(\\\\+.*)?",
                case_insensitive=False,
            ),
        ]
    }


def test_regkey_search_ignore_sid_alias_subdirs_trailing_abs(monkeypatch, mock_search):
    s = searcher(
        monkeypatch,
        regkeysearch_options={
            RegKeySearchOption.SearchHiveAliases,
            RegKeySearchOption.IgnoreSID,
            RegKeySearchOption.AllowRegexp,
            RegKeySearchOption.MatchSubdirs,
            RegKeySearchOption.IgnoreTrailingSlash,
        },
    )
    stix = {
        "key": "HKLM\\Security\\SAM\\Domains\\Builtin\\Aliases\\Members\\S-1-5-80-12345678-901234567-12345689-23456789\\foo\\bar",
    }
    result = s.query_reg_key(stix_entity=stix)
    assert result == {
        "should": [
            Regexp(
                field="data.win.eventdata.targetObject",
                query="(HKEY_LOCAL_MACHINE|HKLM)\\\\+Security\\\\+SAM\\\\+Domains\\\\+Builtin\\\\+Aliases\\\\+Members\\\\+S-1-[0-59]-[0-9]{2}-[0-9]{8,10}-[0-9]{8,10}-[0-9]{8,10}-[1-9][0-9]{3,9}\\\\+foo\\\\+bar(\\\\+.*)?",
                case_insensitive=False,
            ),
            Regexp(
                field="syscheck.path",
                query="(HKEY_LOCAL_MACHINE|HKLM)\\\\+Security\\\\+SAM\\\\+Domains\\\\+Builtin\\\\+Aliases\\\\+Members\\\\+S-1-[0-59]-[0-9]{2}-[0-9]{8,10}-[0-9]{8,10}-[0-9]{8,10}-[1-9][0-9]{3,9}\\\\+foo\\\\+bar(\\\\+.*)?",
                case_insensitive=False,
            ),
        ]
    }
