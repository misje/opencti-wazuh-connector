#!/bin/python3
import os
import sys

sys.path.insert(0, os.path.abspath("../../src"))
from wazuh.config import Config
from wazuh.opensearch_config import OpenSearchConfig
from wazuh.utils import merge_outof


def osConf(**kwargs):
    return OpenSearchConfig(
        **merge_outof(
            kwargs,
            url="http://example.org",
            username="foosername",
            password="fooserpass",
        )
    )


def conf(**kwargs):
    return Config(
        **merge_outof(kwargs, opensearch=osConf(), app_url="http://example.org/foo")
    )
