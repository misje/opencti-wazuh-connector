.. _opencti-compose:

OpenCTI docker-compose example
==============================

The following docker-compose examples fires up OpenCTI with all its
dependencies, and some of its included connectors. It also includes an example
setup of opencti-wazuh-connector, with placeholder values that you need to
replace:

- WAZUH_OPENSEARCH_URL
- WAZUH_OPENSEARCH_USERNAME
- WAZUH_OPENSEARCH_PASSWORD

.. note:: See :ref:`configuration <config>` for details.

.. literalinclude:: opencti-compose.yml
   :language: yaml
   :linenos:

.. note::

   The default login is

   - Username: **admin@opencti.io**
   - Password: TODO
