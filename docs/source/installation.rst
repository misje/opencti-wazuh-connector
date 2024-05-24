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

After starting OpenCTI, look for any errors (get a continuous log with a
little bit of history by running ``docker compose logs -f --tail=100
connector-wazuh``).

.. include:: alpha_warning.rst

.. _versioning:

Versioning
~~~~~~~~~~

The following tags are published to the docker registry:

.. list-table:: Connector docker tags
   :header-rows: 1

   * - Tag
     - Description
   * - x.y.z
     - A connector (stable) release
   * - dev
     - Latest development version (branch *dev*) of the connector
   * - latest
     - The lastest release (à la tag 0.1.0) of the connector

Use a version like *0.1.0* to reference a stable version of the connector, or
*latest* if you want the latest stable version. There are no tags that
reference the OpenCTI version, like connectors published by OpenCTI. See
:ref:`versions and compatibility <versions>` for a connector–OpenCTI version
compatibility list.

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
