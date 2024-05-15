.. _config-reference:

Configuration reference
=======================

The connector has a plethora of configuration options, allowing for detailed
customisation in searching and enrichment. There are some settings you
:ref:`have to <required-settings>` set (there are no defaults, like
usernames and passwords), and there are some settings you :ref:`should
<important-settings>` read about and possibly adjust, since they greatly affect
the behaviour of the connector.

Main configuration
------------------

.. automodule:: wazuh.config
   :members:

OpenCTI configuration
---------------------

OPENCTI settings
^^^^^^^^^^^^^^^^

.. automodule:: wazuh.opencti_config
   :members:

CONNECTOR settings
^^^^^^^^^^^^^^^^^^

.. automodule:: wazuh.connector_config
   :members:

OpenSearch configuration
------------------------

.. automodule:: wazuh.opensearch_config
   :members:

Search configuration
--------------------

Look at :ref:`the alert search topic <alert_search>` for details.

.. automodule:: wazuh.search_config
   :members:

Enrichment configuration
------------------------

Look at :ref:`the enrichment topic <enrichment>` for details.

.. autopydantic_settings:: wazuh.enrich_config.EnrichmentConfig
   :settings-show-json-error-strategy: coerce

Wazuh API configuration
-----------------------

Wazuh API is only partially supported.

.. automodule:: wazuh.wazuh_api_config
   :members:
