#!/bin/python3
import os
import sys
import pytest
from pydantic import ValidationError

sys.path.insert(0, os.path.abspath("../../src"))
from wazuh.opencti_config import OpenCTIConfig


def test_missing_throws():
    with pytest.raises(ValidationError):
        OpenCTIConfig()


def test_nomissing_nothrow():
    OpenCTIConfig(url="http://foo.bar", token="baz", ssl_verify=True)
