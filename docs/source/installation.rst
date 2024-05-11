.. _installation:

Installation
============

This installation documentation assumes that you already have Wazuh installed.
If you do not already have OpenCTI installed, please follow the project's
:octid:`installation instructions (docker) <installation/#using-docker>`. If
you are running or planning to install OpenCTI manually, i.e. not in docker,
note that all of the installation documentation for this connector is written
for docker-compose.

Using the following as an example, add a *connector-wazuh* service to your
OpenCTI docker-compose file:

.. literalinclude:: connector-compose-simple.yml

.. warning::

   This is a bare-minimum example with several placeholder values. Look at the
   :ref:`Configuration <config>` chapter for how to configure the connector.

After starting OpenCTI, look for any errors (get a continuous log wit ha
little bit of history by running ``docker-compose logs -f --tail=100
connector-wazuh``).

.. include:: alpha_warning.rst

Versioning
~~~~~~~~~~

See :ref:`versions and compatibility <versions>` for a connector–OpenCTI
version compatibility list. docker tags matching OpenCTI version will be
provided in the future.

Creating users
~~~~~~~~~~~~~~

Before running the connector, you need to create an OpenCTI user and generate a
token, as well as create an OpenSearch read-only user:

.. toctree::
   :maxdepth: 2
   
   create_opensearch_user
   create_opencti_user

Finishing touches
~~~~~~~~~~~~~~~~~

In order to get the most out of OpenCTI along with this connector, you may want
to go through a few settings and customisation in OpenCTI:

.. toctree::
   :maxdepth: 2

   opencti_configuration
