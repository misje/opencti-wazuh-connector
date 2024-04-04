import doctest
import wazuh.stix_helper
import wazuh.utils

if __name__ == "__main__":
    doctest.testmod(wazuh.stix_helper)
    doctest.testmod(wazuh.utils)
