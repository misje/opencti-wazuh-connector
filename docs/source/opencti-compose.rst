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

In addition to the docker-compose.yml file above, you need an .env file for
common environment variables needed by OpenCI:

.. literalinclude:: opencti-env.env
   :language: bash
   :linenos:

.. note::

   All passwords in docker and docker-compose files must have their "**$**"
   escaped by another "$" (i.e. "$" becomes "$$").

.. note::

   The default login is as you specified in .env (see above). The defaults in
   the example above is:

   - Username: **admin@opencti.io**
   - Password: **SecretPassword**
