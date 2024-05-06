Configuration file location
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The only currently supported way of specifying configuration is through
environment variables. These are typically set in .env files or in the
docker-compose.yml `environment section
<https://docs.docker.com/compose/compose-file/compose-file-v3/#environment>`_.
See :ref:`full docker-compose example <connector-compose-full>` for a complete
connector docker-compose example.

All the configuration variables are references by capitalising their name,
prefixed by either "WAZUH\_", "WAZUH_SEARCH\_", "WAZUH_ENRICH\_" etc. See
*env_prefix* in the various class references. OpenCTI settings are FIXME.

Example:

.. code-block::

   - "WAZUH_AUTHOR_NAME=Wazuh SIEM"
   - WAZUH_BUNDLE_ABORT_LIMIT=200
   - WAZUH_OPENSEARCH_USERNAME=cti_connector
   - "WAZUH_OPENSEARCH_PASSWORD=MyPa$$$$word"
   - WAZUH_SEARCH_LOOKUP_AGENT_IP=false
   - WAZUH_ENRICH_TYPES=file,attack-pattern

See :ref:`the connector docker-compose example <connector-compose>` for a more
complete example.

.. note::

   Escape the whole expression in quotes when the string contains spaces

.. note::

   '$' must be escaped by another '$'. "MyPa$$word" therefore becomes
   "MyPa$$$$word". This is necessary to prevent docker from interpreting the
   dollar sign as `environment variable substitution
   <https://docs.docker.com/compose/compose-file/compose-file-v3/#variable-substitution>`_.

.. note::

   Complicated types, like set of enums or other nested types must either be
   written as JSON, or in most cases, as a simplified comma-separated
   expression. Look at the individual setting documentation for alternative
   formats.

