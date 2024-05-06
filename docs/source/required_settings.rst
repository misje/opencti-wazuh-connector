.. _required-settings:

Required settings
~~~~~~~~~~~~~~~~~

All required settings are marked *[Required]* in the :ref:`configuration
reference <config-reference>`.

- OPENCTI_URL
- OPENCTI_TOKEN
- CONNECTOR_ID
- CONNECTOR_NAME=Wazuh
- CONNECTOR_SCOPE
- CONNECTOR_AUTO=true
- :attr:`OpenSearch URL <wazuh.opensearch_config.OpenSearchConfig.url>`
- :attr:`OpenSearch username <wazuh.opensearch_config.OpenSearchConfig.username>`
- :attr:`OpenSearch password <wazuh.opensearch_config.OpenSearchConfig.password>`
- :attr:`Wazuh URL <wazuh.config.Config.app_url>`
- :attr:`Max TLP <wazuh.config.Config.max_tlp>`

See :ref:`common connector settings <common-connector-settings>` for a
reference for OpenCTI-specific and common connector settings (those prefixed by
*OPENCTI_* and *CONNECTOR_*).

The following scopes are supported by the connector (read more in the
:ref:`alert search <alert_search>` section):

.. include:: supported_entities.rst
