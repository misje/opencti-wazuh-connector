#!/bin/python3
import os
import sys

# import pytest
from pydantic import AnyHttpUrl
from enum import Enum
# from unittest import mock

sys.path.insert(0, os.path.abspath("../../src"))
from wazuh.config_base import ConfigBase
from wazuh.opensearch_dsl import (
    OrderBy,
    Match,
    SortOrder,
)


class FooEnum(Enum):
    Foo = "foo"
    Bar = "bar"
    Baz = "baz"


class FooSettings(ConfigBase):
    foo_set_enum: set[FooEnum] = {FooEnum.Foo}
    foo_str: str = ""
    foo_set_str: set[str] = {"foo"}
    foo_list_str: list[str] = ["foo"]
    foo_list_enum: list[FooEnum] = []
    foo_list_orderby: list[OrderBy] = []
    foo_list_match: list[Match] = []
    foo_http_url: AnyHttpUrl = AnyHttpUrl("http://foo")


# @mock.patch.dict(os.environ, {"WAZUH_FOO_STR": "bar"}, clear=True)
def test_baseconf_inherit_simple_field(monkeypatch):
    monkeypatch.setenv("WAZUH_FOO_STR", "bar")
    conf = FooSettings.from_env()
    assert conf.foo_str == "bar"


# Ensure that ten environment is cleared atfer previous test:
def test_baseconf_inherit_simple_field_cleared():
    conf = FooSettings.from_env()
    assert conf.foo_str == ""


def test_baseconf_inherit_enum_set_json(monkeypatch):
    monkeypatch.setenv("WAZUH_FOO_SET_ENUM", '["bar","baz"]')
    conf = FooSettings.from_env()
    assert conf.foo_str == ""
    assert conf.foo_set_enum == {FooEnum.Bar, FooEnum.Baz}


def test_baseconf_inherit_enum_set_comma_string(monkeypatch):
    monkeypatch.setenv("WAZUH_FOO_SET_ENUM", "bar,baz")
    monkeypatch.setenv("WAZUH_FOO_STR", "qux")
    conf = FooSettings.from_env()
    assert conf.foo_set_enum == {FooEnum.Bar, FooEnum.Baz}
    assert conf.foo_str == "qux"


def test_baseconf_inherit_enum_set_all(monkeypatch):
    monkeypatch.setenv("WAZUH_FOO_SET_ENUM", "all")
    conf = FooSettings.from_env()
    assert conf.foo_set_enum == {FooEnum.Foo, FooEnum.Bar, FooEnum.Baz}


def test_baseconf_inherrit_enum_set_case(monkeypatch):
    monkeypatch.setenv("WAZUH_FOO_SET_ENUM", "foo,BAR,   bAZ")
    conf = FooSettings.from_env()
    assert conf.foo_set_enum == {FooEnum.Foo, FooEnum.Bar, FooEnum.Baz}


def test_baseconf_set_str_json(monkeypatch):
    monkeypatch.setenv("WAZUH_FOO_SET_STR", '["foo", "bar", "bar"]')
    conf = FooSettings.from_env()
    assert conf.foo_set_str == {"foo", "bar"}


def test_baseconf_set_str_comma_string(monkeypatch):
    monkeypatch.setenv("WAZUH_FOO_SET_STR", "foo,bar,bar")
    conf = FooSettings.from_env()
    assert conf.foo_set_str == {"foo", "bar"}


# 'all' is notthing special for 'str', just enums:
def test_baseconf_set_str_all(monkeypatch):
    monkeypatch.setenv("WAZUH_FOO_SET_STR", "all")
    conf = FooSettings.from_env()
    assert conf.foo_set_str == {"all"}


def test_baseconf_list_str_json(monkeypatch):
    monkeypatch.setenv("WAZUH_FOO_LIST_STR", '["foo", "bar"]')
    conf = FooSettings.from_env()
    assert conf.foo_list_str == ["foo", "bar"]


def test_baseconf_list_str_comma_string(monkeypatch):
    monkeypatch.setenv("WAZUH_FOO_LIST_STR", "foo,bar")
    conf = FooSettings.from_env()
    assert conf.foo_list_str == ["foo", "bar"]


def test_baseconf_list_enum_json(monkeypatch):
    monkeypatch.setenv("WAZUH_FOO_LIST_ENUM", '["foo", "bar"]')
    conf = FooSettings.from_env()
    assert conf.foo_list_enum == [FooEnum.Foo, FooEnum.Bar]


def test_baseconf_list_enum_comma_string(monkeypatch):
    monkeypatch.setenv("WAZUH_FOO_LIST_ENUM", "foo,bar")
    conf = FooSettings.from_env()
    assert conf.foo_list_enum == [FooEnum.Foo, FooEnum.Bar]


def test_baseconf_list_orderby_json(monkeypatch):
    monkeypatch.setenv(
        "WAZUH_FOO_LIST_ORDERBY",
        '[{"field": "rule.level", "order": "desc"}, {"field": "timestamp", "order": "desc"}]',
    )
    conf = FooSettings.from_env()
    assert conf.foo_list_orderby == [
        OrderBy(field="rule.level", order=SortOrder.Desc),
        OrderBy(field="timestamp", order=SortOrder.Desc),
    ]


def test_baseconf_list_orderby_comma_string(monkeypatch):
    monkeypatch.setenv("WAZUH_FOO_LIST_ORDERBY", "rule.level:desc,timestamp:desc")
    conf = FooSettings.from_env()
    assert conf.foo_list_orderby == [
        OrderBy(field="rule.level", order=SortOrder.Desc),
        OrderBy(field="timestamp", order=SortOrder.Desc),
    ]


def test_baseconf_http_url(monkeypatch):
    monkeypatch.setenv("WAZUH_FOO_HTTP_URL", "http://bar.baz")
    conf = FooSettings.from_env()
    assert conf.foo_http_url == AnyHttpUrl("http://bar.baz")
