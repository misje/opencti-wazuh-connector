.. _connector-compose:

Connector docker-compose example
================================

The following is an extract from a docker-compose.yml with only the connector
service. See :ref:`the OpenCTI docker-compose example <opencti-compose>` for a
more complete example.

.. warning::

   opencti-wazuh-connector is in an early alpha stage. Although the connector
   does not make any changes to Wazuh, it may produce a lot of data in OpenCTI.
   Do not use the connector yet in production.

.. literalinclude:: connector-compose-simple.yml
   :language: yaml
   :linenos:

.. _connector-compose-full:

The following expands on the example above, with most or all available settings
with their default values:

.. literalinclude:: connector-compose.yml
   :language: yaml
   :linenos:

See :ref:`configuration <config>` for configuration details and a full
reference.

.. warning::

   The docker-compose example is just that, an example. You **must** understand
   at least the :ref:`most important settings <required-settings>` before using
   the connector.

.. note::

   This example is not necessarily a complete reference of all possible
   settings.
