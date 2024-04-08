#!/bin/python3
import os
import sys
import pytest
import random
import json
from pydantic import AnyHttpUrl, ValidationError
from datetime import datetime
from wazuh.utils import merge_outof

sys.path.insert(0, os.path.abspath("../../src"))
from wazuh.opensearch_config import OpenSearchConfig

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


def osConf(**kwargs):
    return OpenSearchConfig(
        **merge_outof(
            kwargs,
            url="http://example.org",
            username="foosername",
            password="fooserpass",
        )
    )


def test_lax_datetime_parsing(timestamp_like_string):
    osConf(search_after=timestamp_like_string)


def test_invalid_lax_datetime_parsing():
    with pytest.raises(ValidationError):
        osConf(search_after="foo")


def test_datetime_datetime_parsing():
    osConf(search_after=datetime.fromisoformat("2024-04-05T19:22:03"))


def test_match_patterns_parsing():
    c = osConf(include_match="foo=bar,baz=qux")
    assert c.include_match == [{"match": {"foo": "bar"}}, {"match": {"baz": "qux"}}]


def test_os_valid_url_str():
    osConf(url="http://@example.org")


def test_os_url_with_credentials_throw():
    with pytest.raises(ValidationError):
        osConf(url="http://username:password@example.org")


def test_os_url_with_params_throw():
    with pytest.raises(ValidationError):
        osConf(url="http://example.org?foo=bar")


def test_exclude_match_default():
    assert osConf().exclude_match == [{"match": {"data.integration": "opencti"}}]


def test_exclude_match_str():
    c = osConf(exclude_match="foo=bar,baz=qux")
    assert c.exclude_match == [{"match": {"foo": "bar"}}, {"match": {"baz": "qux"}}]


def test_exclude_match_dsl():
    dsl = [{"match": {"foo": "bar"}}]
    c = osConf(exclude_match=json.dumps(dsl))
    assert c.exclude_match == dsl


def test_order_by_default():
    assert osConf().order_by == [{"timestamp": {"order": "desc"}}]


def test_order_by_str():
    c = osConf(order_by="rule.level=asc,timestamp=desc")
    assert c.order_by == [
        {"rule.level": {"order": "asc"}},
        {"timestamp": {"order": "desc"}},
    ]


def test_order_by_invalid_raises():
    with pytest.raises(ValidationError):
        osConf(order_by="foo,bar")


# class Fjas:
#    def __init__(
#        self,
#        *,
#        url: str,
#        username: str,
#        password: str,
#        limit: int,
#        index: str,
#        filters: list[dict[str, dict]] = [],
#        search_after: datetime | None,
#        order_by: list[dict] = [],
#        include_match: list[dict] | None,
#        exclude_match: list[dict] | None,
#    ) -> None:
#        self.url = url
#        self.username = username
#        self.password = password
#        self.index = index
#        self.limit = limit
#        self.filters = filters
#        self.search_after = search_after
#        self.order_by = order_by
#        self.include_match = include_match
#        self.exclude_match = exclude_match
#
#
# def test_fjas():
#    c = osConf()
#    print(c.model_dump())
#    f = Fjas(**c.model_dump())
#    print(f)
