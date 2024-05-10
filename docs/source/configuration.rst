.. _config:

Configuration
=============

The connector has a plethora of configuration options, allowing for detailed
customisation in searching and enrichment. There are some settings you
:ref:`have to <required-settings>` set (there are no defaults, like
usernames and passwords), and there are some settings you :ref:`should
<important-settings>` read about and possibly adjust, since they greatly affect
the behaviour of the connector.

Configuration sources
---------------------

TODO: docker: docker-compose and .env. non-docker: config.yml

.. seealso::

      See :ref:`OpenCTI configuration <opencti-configuration>` for
      configuration/customisation of OpenCTI.

.. toctree::
   :maxdepth: 2

   common_connector_settings
   config_file_location
   required_settings
   important_settings
   conf_other_considerations
   config_reference
