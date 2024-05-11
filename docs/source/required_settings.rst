.. _required-settings:

Required settings
~~~~~~~~~~~~~~~~~

The following settings **must** be set, as they have no
default values. If you have followed the :ref:`installation
instructions <installation>`, you should already have the
necessary users, passwords and tokens ready.

All required settings are marked *[Required]* in the :ref:`configuration
reference <config-reference>`.

.. list-table:: Required settings
   :header-rows: 1

   * - Env. var.
     - Setting name
     - Description
   * - OPENCTI_URL
     - :attr:`opencti.url <wazuh.opencti_config.OpenCTIConfig.url>`
     - OpenCTI URL
   * - OPENCTI_TOKEN
     - :attr:`opencti.token <wazuh.opencti_config.OpenCTIConfig.token>`
     - See `create OpenCTI user <create-opencti-user>`
   * - CONNECTOR_ID
     - :attr:`connector.id <wazuh.connector_config.ConnectorConfig.id>`
     - Any unique identifier, like a UUID
   * - CONNECTOR_SCOPE
     - :attr:`connector.scope <wazuh.connector_config.ConnectorConfig.scope>`
     - Which :ref:`entities the connector should accept <supported-entities>`.
   * - CONNECTOR_AUTO
     - :attr:`connector.auto <wazuh.connector_config.ConnectorConfig.auto>`
     - Whether to run automatically or manually. See :ref:`when to run <when-to-run>`.
   * - OPENSEARCH_URL
     - :attr:`opensearch.url <wazuh.opensearch_config.OpenSearchConfig.url>`
     - Wazuh OpenSearch URL (typically the app URL + *:9200*)
   * - OPENSEARCH_USERNAME
     - :attr:`opensearch.username <wazuh.opensearch_config.OpenSearchConfig.username>`
     - See :ref:`create OpenSearch user <create-opensearch-user>`
   * - OPENSEARCH_PASSWORD
     - :attr:`opensearch.password <wazuh.opensearch_config.OpenSearchConfig.password>`
     - See :ref:`create OpenSearch user <create-opensearch-user>`
   * - APP_URL
     - :attr:`url <wazuh.config.Config.app_url>`
     - Wazuh URL used to create links
   * - MAX_TLP
     - :attr:`max_tlp <wazuh.config.Config.max_tlp>`
     - The highest :term:`marking definition` the connector should be
       entrusted

The following scopes are supported by the connector (read more in the
:ref:`alert search <alert_search>` section):

.. include:: supported_entities.rst
