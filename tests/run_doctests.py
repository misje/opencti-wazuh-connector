#!/bin/python3
import os
import sys

sys.path.insert(0, os.path.abspath("../src"))
import doctest
import wazuh.stix_helper
import wazuh.utils
import wazuh.config


if __name__ == "__main__":
    doctest.testmod(wazuh.stix_helper)
    doctest.testmod(wazuh.utils)
    doctest.testmod(wazuh.config)
