#!/bin/python3
import os
import sys
import pytest
from pydantic import ValidationError

sys.path.insert(0, os.path.abspath("../../src"))
from wazuh.search_config import SearchConfig


@pytest.fixture(
    params=[
        "case-insensitive",
    ]
)
def filesearch_opts_requiring_regexp(request):
    return request.param


@pytest.fixture(
    params=[
        "match-subdirs",
        "search-filenames",
        "case-insensitive",
        "ignore-trailing-slash",
    ]
)
def dirsearch_opts_requiring_regexp(request):
    return request.param


def test_default_nothrow():
    SearchConfig()


def test_file_noregexp_throw(filesearch_opts_requiring_regexp):
    with pytest.raises(ValidationError):
        SearchConfig(filesearch_options=filesearch_opts_requiring_regexp)


def test_dir_noregexp_throw(dirsearch_opts_requiring_regexp):
    with pytest.raises(ValidationError):
        SearchConfig(dirsearch_options=dirsearch_opts_requiring_regexp)
