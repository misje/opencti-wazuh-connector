#!/bin/python3
import os
import sys
import pytest
import random
from pydantic import ValidationError
from datetime import datetime

sys.path.insert(0, os.path.abspath("../../src"))
from wazuh.config import Config

# random.seed(0)

tlp_colours = ["clear", "white", "green", "amber", "amber+strict", "red"]
boolean_true = [
    "true",
    "True",
    "yes",
    "Yes",
    "1",
    True,
    1,
]
boolean_false = [
    "false",
    "False",
    "no",
    "No",
    "0",
    False,
    0,
]
timestampshs = [
    "1 week ago",
    "2024-01-02",
    "2024-04-05T19:22:03.348450",
    "2024-04-05T19:22:03.348450Z",
    "four months ago",
]


def randomise_case(string: str) -> str:
    return "".join(random.choice((c.upper(), c.lower(), c)) for c in string)


@pytest.fixture(params=["tlp:", ""])
def tlp_prefix(request) -> str:
    return randomise_case(request.param)


@pytest.fixture(params=tlp_colours)
def tlp_colour(request) -> str:
    return randomise_case(request.param)


@pytest.fixture
def tlp(tlp_prefix, tlp_colour):
    return tlp_prefix + tlp_colour


@pytest.fixture(params=boolean_true)
def trueish(request):
    return request.param


@pytest.fixture(params=boolean_false)
def falseish(request):
    return request.param


@pytest.fixture
def all_tlps():
    return [
        randomise_case(prefix) + randomise_case(colour)
        for prefix in ["tlp:", ""]
        for colour in tlp_colours
    ]


@pytest.fixture(params=[1, len(tlp_colours)])
def random_tlps(request, all_tlps):
    return random.choices(all_tlps, k=request.param)


@pytest.fixture(params=timestampshs)
def timestamp_like_string(request):
    return request.param


def test_valid_max_tlp_values(all_tlps):
    # Doesn't raise:
    [Config(max_tlp=tlp) for tlp in all_tlps]


def test_valid_max_raises():
    with pytest.raises(ValidationError):
        Config(max_tlp="foo")  # type:ignore


def test_valid_tlps_list(tlp, random_tlps):
    Config(max_tlp=tlp, tlps=random_tlps)


def test_valid_tlps_set(tlp, random_tlps):
    Config(max_tlp=tlp, tlps=set(random_tlps))


def test_valid_tlps_comma_string(tlp, random_tlps):
    Config(max_tlp=tlp, tlps=",".join(random_tlps))  # type: ignore


def test_invalid_tlps_string(tlp):
    with pytest.raises(ValidationError):
        Config(max_tlp=tlp, tlps="foo")  # type: ignore


def test_boolean_arg_true(trueish):
    assert Config(max_tlp="TLP:WHITE", order_by_rule_level=trueish).order_by_rule_level


def test_boolean_arg_flase(falseish):
    assert not Config(
        max_tlp="TLP:WHITE", order_by_rule_level=falseish
    ).order_by_rule_level


def test_abort_hits_below_limit_raises():
    with pytest.raises(ValidationError):
        Config(max_tlp="TLP:WHITE", hits_limit=10, hits_abort_limit=9)


def test_abort_hits_none():
    Config(max_tlp="TLP:WHITE", hits_abort_limit=None)


def test_lax_datetime_parsing(timestamp_like_string):
    Config(max_tlp="TLP:WHITE", search_after=timestamp_like_string)


def test_invalid_lax_datetime_parsing():
    with pytest.raises(ValidationError):
        Config(max_tlp="TLP:WHITE", search_after="foo")  # type: ignore


def test_datetime_datetime_parsing():
    Config(
        max_tlp="TLP:WHITE", search_after=datetime.fromisoformat("2024-04-05T19:22:03")
    )


def test_match_patterns_parsing():
    c = Config(max_tlp="TLP:WHITE", search_include="foo=bar,baz=qux")
    assert c.search_include == [{"match": {"foo": "bar"}}, {"match": {"baz": "qux"}}]


def test_max_refs_below_limit_raises():
    with pytest.raises(ValidationError):
        Config(max_tlp="TLP:WHITE", max_extrefs=1, max_extrefs_per_alert_rule=2)


def test_max_notes_below_limit_raises():
    with pytest.raises(ValidationError):
        Config(max_tlp="TLP:WHITE", max_notes=1, max_notes_per_alert_rule=2)
