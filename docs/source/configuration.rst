.. _config:

Configuration
=============

The connector needs to be configured before you can use it. At the very least,
you need to specify URLs, usernames, passwords and tokens. It is expected that
most users of this connector is running the connector, with or without the rest
of OpenCTI, in :term:`docker`, using `docker-compose
<https://docs.docker.com/compose/compose-file/>`_. Configuring the connector in
docker-compose can be done in one of two ways:

- Environment variables specified as key–value entries as *key=value* on
  individual lines in an .env file (in the same directory as
  docker-compose.yml). The file may be named different, depending on
  :dcompose:`env_file <env_file>` on docker-compose.yml.
- Directly specified in :dcompose:`environment <environment>` in the
  docker-compose.yml file, for the connector service.

If you need to run the connector without using docker, you may also use a YAML
or JSON configuration file. See :ref:`YAML configuration <yaml-config>` for an
example.


.. toctree::
   :maxdepth: 2

   env-config
   yaml-config
   required_settings
   important_settings
   conf_other_considerations
   config_reference
