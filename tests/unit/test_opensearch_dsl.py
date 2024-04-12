#!/bin/python3
import os
import sys
import pytest
import random
import json
from pydantic import ValidationError
from typing import TypeAlias

sys.path.insert(0, os.path.abspath("../../src"))
from wazuh.opensearch_dsl import (
    Bool,
    Exists,
    Match,
    MultiMatch,
    OrderBy,
    Query,
    Range,
    Regexp,
    SortOrder,
    Term,
    Wildcard,
)

# random.seed(0)


def test_complex_valid_query():
    q = Query(
        query=Bool(
            must=[
                Wildcard(field="bwf", query="bwq"),
                Regexp(field="brf", query="brq"),
                Match(field="bmf", query="bmq"),
                MultiMatch(fields=["bmmf1", "bmmf2"], query="bmmq"),
                Bool(
                    must=[Regexp(field="bbrf", query="bbrq")],
                    must_not=[Wildcard(field="bbwf", query="bbwq")],
                    should=[Bool(should=[Match(field="foo", query="bar")])],
                ),
            ]
        )
    )
    expected = json.loads(
        """
    {
       "query": {
          "bool": {
             "must": [
                {
                   "wildcard": {
                      "bwf": {
                         "value": "bwq",
                         "case_insensitive": false
                      }
                   }
                },
                {
                   "regexp": {
                      "brf": {
                         "value": "brq",
                         "case_insensitive": false
                      }
                   }
                },
                {
                   "match": {
                      "bmf": "bmq"
                   }
                },
                {
                   "multi_match": {
                      "query": "bmmq",
                      "fields": [
                         "bmmf1",
                         "bmmf2"
                      ]
                   }
                },
                {
                   "bool": {
                      "must": [
                         {
                            "regexp": {
                               "bbrf": {
                                  "value": "bbrq",
                                  "case_insensitive": false
                               }
                            }
                         }
                      ],
                      "must_not": [
                         {
                            "wildcard": {
                               "bbwf": {
                                  "value": "bbwq",
                                  "case_insensitive": false
                               }
                            }
                         }
                      ],
                      "should": [
                         {
                            "bool": {
                               "must": [],
                               "must_not": [],
                               "should": [
                                  {
                                     "match": {
                                        "foo": "bar"
                                     }
                                  }
                               ],
                               "filter": [],
                               "minimum_should_match": null
                            }
                         }
                      ],
                      "filter": [],
                      "minimum_should_match": null
                   }
                }
             ],
             "must_not": [],
             "should": [],
             "filter": [],
             "minimum_should_match": null
          }
       }
    }
    """
    )

    assert q.model_dump(exclude_none=True, exclude_unset=True) == expected


def test_empty_bool_throws():
    with pytest.raises(ValidationError):
        Bool()


def test_range():
    expected = {"range": {"field": "foo", "gt": "2024", "lt": "2023", "boost": 1.0}}
    range = Range(field="foo", gt="2024", lt="2023").model_dump(exclude_none=True)
    assert range == expected


def test_range_wo_op_throws():
    with pytest.raises(ValidationError):
        Range(field="foo")


def test_range_wo_field_throws():
    with pytest.raises(ValidationError):
        Range(field=None, lte="asd")  # type: ignore


def test_order_by_str():
    o = OrderBy(field="foo", order="desc")
    assert o.order == SortOrder.Desc


def test_query():
    Query(
        query=Match(field="foo", query="bar"),
        size=10,
        sort=[OrderBy(field="baz", order=SortOrder.Desc)],
    )
