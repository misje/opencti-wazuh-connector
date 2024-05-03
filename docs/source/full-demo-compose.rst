.. _full-demo-compose:

Complete Wazuh+OpenCTI docker-compose example
=============================================

In addition to running an OpenCTI instance with opencti-wazuh-connector, this
docker-compose example file also runs Wazuh in a single-node deployment with
example data. No change to the docker-compose file is strictly needed to test
the demo.

TODO: example data + @timestamp script

.. literalinclude:: full-demo-compose.yml
   :language: yaml
   :linenos:

.. note::

   The default **Wazuh** login is

   - Username: **admin**
   - Password: **SecretPassword**

.. note::

   The default **OpenCTI** login is

   - Username: **admin@opencti.io**
   - Password: TODO

.. note::

   The provided example data is not visible in the *Wazuh* app, but it can be
   browsed in OpenSearch *Discover*.
