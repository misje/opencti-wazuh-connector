#!/bin/python3
import os
import sys

sys.path.insert(0, os.path.abspath("../../src"))
from wazuh.config import Config
from wazuh.opensearch_config import OpenSearchConfig
from wazuh.utils import merge_outof
from wazuh.opencti_config import OpenCTIConfig
from wazuh.connector_config import ConnectorConfig

# TODO: there are more recommended ways to do this in pytest than importing a file


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
        **merge_outof(
            kwargs,
            opensearch=osConf(),
            app_url="http://example.org/foo",
            opencti=OpenCTIConfig(url="http://foo.bar", token="foo"),
            connector=ConnectorConfig(id="foo"),
        )
    )
