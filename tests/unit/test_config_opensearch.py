#!/bin/python3
import os
import sys
import pytest
import random
import json
from pydantic import AnyHttpUrl, ValidationError
from datetime import datetime

sys.path.insert(0, os.path.abspath("../../src"))
from wazuh.opensearch_config import OpenSearchConfig
from test_common import osConf
from wazuh.opensearch_dsl import Match, OrderBy
from wazuh.utils import merge_outof

# random.seed(0)

timestampshs = [
    "1 week ago",
    "2024-01-02",
    "2024-04-05T19:22:03.348450",
    "2024-04-05T19:22:03.348450Z",
    "four months ago",
]


@pytest.fixture(params=timestampshs)
def timestamp_like_string(request):
    return request.param


def test_lax_datetime_parsing(timestamp_like_string):
    osConf(search_after=timestamp_like_string)


def test_invalid_lax_datetime_parsing():
    with pytest.raises(ValidationError):
        osConf(search_after="foo")


def test_datetime_datetime_parsing():
    osConf(search_after=datetime.fromisoformat("2024-04-05T19:22:03"))


# def test_match_patterns_parsing():
#    c = osConf(include_match="foo=bar,baz=qux")
#    assert c.include_match == [{"match": {"foo": "bar"}}, {"match": {"baz": "qux"}}]


def test_os_valid_url_str():
    osConf(url="http://@example.org")


def test_os_url_with_credentials_throw():
    with pytest.raises(ValidationError):
        osConf(url="http://username:password@example.org")


def test_os_url_with_params_throw():
    with pytest.raises(ValidationError):
        osConf(url="http://example.org?foo=bar")


def test_exclude_match_default():
    assert osConf().exclude_match == [Match(field="data.integration", query="opencti")]


def test_exclude_match_str():
    c = osConf(exclude_match="foo=bar,baz=qux")
    assert c.exclude_match == [
        Match(field="foo", query="bar"),
        Match(field="baz", query="qux"),
    ]


def test_exclude_match_dsl():
    dsl = [Match(field="foo", query="bar")]
    c = osConf(exclude_match=dsl)
    assert c.exclude_match == dsl


def test_order_by_default():
    assert osConf().order_by == [OrderBy(field="timestamp", order="desc")]


def test_order_by_str():
    c = osConf(order_by="rule.level:asc,timestamp:desc")
    assert c.order_by == [
        OrderBy(field="rule.level", order="asc"),
        OrderBy(field="timestamp", order="desc"),
    ]


def test_order_by_invalid_raises():
    with pytest.raises(ValidationError):
        osConf(order_by="foo,bar")


def test_order_by_json():
    osConf(order_by=[{"timestamp": {"order": "desc"}}])


def test_exclude_match_json():
    osConf(exclude_match=[{"match": {"data.integration": "opencti"}}])


# Output used in create_summary_note():
def test_exclude_match_dump():
    dump = osConf(exclude_match="foo=bar,baz=qux").field_json("exclude_match")
    expected = '[{"match": {"foo": "bar"}}, {"match": {"baz": "qux"}}]'
    assert dump == expected


def test_exclude_match_dump_empty():
    dump = osConf(exclude_match=None).field_json("exclude_match")
    expected = ""
    assert dump == expected
