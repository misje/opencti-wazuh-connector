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

.. subst_literalinclude:: opencti-compose.yml
   :language: yaml
   :linenos:

.. note::

   If you intend to replace the OpenCTI version in any of the services, ensure
   that the dependencies (redis, elasticsearch, minio, rabbitmq) are also
   updated. Look for historical versions of :octigh:`OpenCTI's
   docker-compose.yml file <docker/blob/master/docker-compose.yml>`.

.. _opencti-env:

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
