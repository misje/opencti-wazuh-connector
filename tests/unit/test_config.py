#!/bin/python3
import os
import sys
import pytest
import random
from pydantic import ValidationError

sys.path.insert(0, os.path.abspath("../../src"))
from wazuh.config import Config, EnrichmentConfig
from test_common import conf

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


def test_valid_max_tlp_values(all_tlps):
    # Doesn't raise:
    [conf(max_tlp=tlp) for tlp in all_tlps]


def test_valid_max_raises():
    with pytest.raises(ValidationError):
        conf(max_tlp="foo")  # type:ignore


def test_valid_tlps_list(tlp, random_tlps):
    conf(max_tlp=tlp, tlps=random_tlps)


def test_valid_tlps_set(tlp, random_tlps):
    conf(max_tlp=tlp, tlps=set(random_tlps))


def test_valid_tlps_comma_string(tlp, random_tlps):
    conf(max_tlp=tlp, tlps=",".join(random_tlps))  # type: ignore


def test_invalid_tlps_string(tlp):
    with pytest.raises(ValidationError):
        conf(max_tlp=tlp, tlps="foo")  # type: ignore


def test_boolean_arg_true(trueish):
    assert conf(max_tlp="TLP:WHITE", agents_as_systems=trueish).agents_as_systems


def test_boolean_arg_flase(falseish):
    assert not conf(max_tlp="TLP:WHITE", agents_as_systems=falseish).agents_as_systems


# def test_abort_hits_below_limit_raises():
#    with pytest.raises(ValidationError):
#        conf(max_tlp="TLP:WHITE", hits_limit=10, hits_abort_limit=9)


def test_abort_hits_none():
    conf(max_tlp="TLP:WHITE", hits_abort_limit=None)


def test_max_refs_below_limit_raises():
    with pytest.raises(ValidationError):
        conf(max_tlp="TLP:WHITE", max_extrefs=1, max_extrefs_per_alert_rule=2)


def test_max_notes_below_limit_raises():
    with pytest.raises(ValidationError):
        conf(max_tlp="TLP:WHITE", max_notes=1, max_notes_per_alert_rule=2)


def test_all_enum_values_in_set():
    c = conf(max_tlp="TLP:WHITE", enrich=EnrichmentConfig(types="all"))  # type: ignore
    etypes = c.enrich.types
    assert etypes == set(EnrichmentConfig.EntityType)


def test_label_ignore_list_set():
    c = conf(max_tlp="white", label_ignore_list={"foo", "bar"})
    assert c.label_ignore_list == {"foo", "bar"}


def test_label_ignore_list_comma_string():
    c = conf(max_tlp="white", label_ignore_list="foo,bar")
    assert c.label_ignore_list == {"foo", "bar"}


def test_label_ignore_list_empty():
    c = conf(max_tlp="white", label_ignore_list="")
    assert c.label_ignore_list == set()


# def test_filename_behaviour_set():
#    c = EnrichmentConfig(filename_behaviour="create-dir")
