.. _connector-compose:

Connector docker-compose example
================================

The following is an extract from a docker-compose.yml with only the connector
service. See :ref:`the OpenCTI docker-compose example <opencti-compose>` for a
more complete example.

.. literalinclude:: connector-compose-simple.yml
   :language: yaml
   :linenos:

The following expands on the example above, with most or all available settings
with their default values:

.. literalinclude:: connector-compose.yml
   :language: yaml
   :linenos:

See :ref:`configuration <config>` for configuration details and a full
reference.

.. warning::

   The docker-compose example is just that, an example. You **must** understand
   at least the most important settings before using the connector.

.. note::

   This example is not necessarily a complete reference of all possible
   settings.
