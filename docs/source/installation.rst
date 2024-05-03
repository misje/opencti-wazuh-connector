.. _installation:

Installation
============

This installation documentation assumes that you already have Wazuh installed.
If you do not aleady have OpenCTI installed, please follow the project's
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
connector-wazuh``.

Building the docker image
~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::

   This is an optional step, and only necessary if you want the latest
   development version of the connector.

If you want the cutting edge development version of the cnnector, first clone
the project from GitHub (no account is needed for this), then build the docker
image:

#. ``git clone https://github.com/mise/opencti-wazuh-connector``
#. ``docker build -t openti-wazuh-connector-dev .``

Then you need to replace the reference to the connector image:

-  Replace the line ``image: ghcr.io/misje/opencti-connector-wazuh:0.1.0`` in
   *docker-compose.yml* with ``image: openti-wazuh-connector-dev``

You may also build the image through ``docker-compose build``/``docker-compose
up -d --build`` as long as the cloned project is in the same directory as
OpenCTI's *docker-compose.yml* and with the following lines instead of the
*image:* directive:

.. code-block:: yaml

    build:
      context: .

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
