#!/bin/python3
import os
import sys
import pytest
from pydantic import ValidationError

sys.path.insert(0, os.path.abspath("../../src"))
from wazuh.opensearch_dsl import Match, OrderBy, Regexp, Wildcard
from wazuh.opensearch_dsl_helper import (
    dsl_multi_regex,
    dsl_multi_wildcard,
    dsl_matches_from_string,
    dsl_order_by_from_string,
)

# random.seed(0)


def test_dsl_multi_regex():
    q = dsl_multi_regex(fields=["foo", "bar"], regexp="query", case_insensitive=True)
    expected = [
        Regexp(field="foo", query="query", case_insensitive=True),
        Regexp(field="bar", query="query", case_insensitive=True),
    ]
    assert q == expected


def test_dsl_multi_wildcard():
    q = dsl_multi_wildcard(fields=["foo", "bar"], query="query", case_insensitive=True)
    expected = [
        Wildcard(field="foo", query="query", case_insensitive=True),
        Wildcard(field="bar", query="query", case_insensitive=True),
    ]
    assert q == expected


def test_dsl_matces_from_string():
    q = dsl_matches_from_string(terms="foo=bar,baz=qux")
    expected = [
        Match(field="foo", query="bar"),
        Match(field="baz", query="qux"),
    ]
    assert q == expected


def test_dsl_order_by_from_string():
    q = dsl_order_by_from_string(terms="foo:asc,bar:desc")
    expected = [
        OrderBy(field="foo", order="asc"),
        OrderBy(field="bar", order="desc"),
    ]
    assert q == expected


def test_dsl_matces_from_string_invalid_throws():
    with pytest.raises(ValueError):
        dsl_matches_from_string(terms="foo")
