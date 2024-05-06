import os
import sys

sys.path.insert(0, os.path.abspath("../src"))
import doctest
import wazuh.stix_helper
import wazuh.utils
import wazuh.config
import wazuh.enrich_config
import wazuh.enrich
import wazuh.opensearch_dsl_helper
import wazuh.opensearch_config
import wazuh.opensearch
import wazuh.search
import wazuh.sightings
import wazuh.wazuh_api_config
import wazuh.wazuh


if __name__ == "__main__":
    doctest.testmod(wazuh.stix_helper)
    doctest.testmod(wazuh.utils)
    doctest.testmod(wazuh.config)
    doctest.testmod(wazuh.enrich_config)
    doctest.testmod(wazuh.enrich)
    doctest.testmod(wazuh.opensearch_dsl_helper)
    doctest.testmod(wazuh.opensearch_config)
    doctest.testmod(wazuh.opensearch)
    doctest.testmod(wazuh.search)
    doctest.testmod(wazuh.sightings)
    doctest.testmod(wazuh.wazuh)
