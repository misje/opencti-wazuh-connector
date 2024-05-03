.. _config:

Configuration
=============

The connector has a plethora of configuration options, allowing for detailed
customisation in searching and enrichment. There are some settings you
:ref:`have to <required-settings>` set (there are no defaults, like
usernames and passwords), and there are some settings you :ref:`should
<important-settings>` read about and possibly adjust, since they greatly affect
the behaviour of the connector.

.. seealso::

   See :ref:`common connector settings <common-connector-settings>` for OpenCTI
   settings not covered in this reference.

.. toctree::
   :hidden:

   common_connector_settings

.. seealso::

      See :ref:`OpenCTI configuration <opencti-configuration>` for
      configuration/customisation of OpenCTI.

Configuration file location
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The only currently supported way of specifying configuration is through
environment variables. These are typically set in .env files or in the
docker-compose.yml `environment section
<https://docs.docker.com/compose/compose-file/compose-file-v3/#environment>`_.
See FIXME for a complete connector docker-compose example.

All the configuration variables are references by capitalising their name,
prefixed by either "WAZUH\_", "WAZUH_SEARCH\_", "WAZUH_ENRICH\_" etc. See
*env_prefix* in the various class references. OpenCTI settings are FIXME.

Example:

.. code-block::

   - "WAZUH_AUTHOR_NAME=Wazuh SIEM"
   - WAZUH_BUNDLE_ABORT_LIMIT=200
   - WAZUH_OPENSEARCH_USERNAME=cti_connector
   - "WAZUH_OPENSEARCH_PASSWORD=MyPa$$$$word"
   - WAZUH_SEARCH_LOOKUP_AGENT_IP=false
   - WAZUH_ENRICH_TYPES=file,attack-pattern

See :ref:`the connector docker-compose example <connector-compose>` for a more
complete example.

.. note::

   Escape the whole expression in quotes when the string contains spaces

.. note::

   '$' must be escaped by another '$'. "MyPa$$word" therefore becomes
   "MyPa$$$$word". This is necessary to prevent docker from interpreting the
   dollar sign as `environment variable substitution
   <https://docs.docker.com/compose/compose-file/compose-file-v3/#variable-substitution>`_.

.. note::

   Complicated types, like set of enums or other nested types must either be
   written as JSON, or in most cases, as a simplified comma-separated
   expression. Look at the individual setting documentation for alternative
   formats.

.. _required-settings:

Required settings
~~~~~~~~~~~~~~~~~

All required settings are marked *[Required]* in the :ref:`configuration
reference <config-reference>`.

- OPENCTI_URL
- OPENCTI_TOKEN
- CONNECTOR_ID
- CONNECTOR_NAME=Wazuh
- CONNECTOR_SCOPE
- CONNECTOR_AUTO=true
- :attr:`OpenSearch URL <wazuh.opensearch_config.OpenSearchConfig.url>`
- :attr:`OpenSearch username <wazuh.opensearch_config.OpenSearchConfig.username>`
- :attr:`OpenSearch password <wazuh.opensearch_config.OpenSearchConfig.password>`
- :attr:`Wazuh URL <wazuh.config.Config.app_url>`
- :attr:`Max TLP <wazuh.config.Config.max_tlp>`

See :ref:`common connector settings <common-connector-settings>` for a
reference for OpenCTI-specific and common connector settings (those prefixed by
*OPENCTI_* and *CONNECTOR_*).

The following scopes are supported by the connector (read more in the
:ref:`alert search <alert_search>` section):

.. include:: supported_entities.rst

.. _important-settings:

Important settings
~~~~~~~~~~~~~~~~~~

After having configured the required settings, you should at minimum read up on
and adjust the following settings:

TLS verification
----------------

FIXME: replace with first-time cert import?:

- :attr:`Verify OpenSearch TLS certificate <wazuh.opensearch_config.OpenSearchConfig.verify_tls>`

Searching
---------

:attr:`search.limit <wazuh.opensearch_config.OpenSearchConfig.limit>`

   Maximum number of alerts to return from a search

:attr:`~wazuh.config.Config.hits_abort_limit`

   Number of alert matches (reported by OpenSearch, not the number of results
   returned) that should abort further processing. This limit helps preventing
   flooding OpenCTI with events from bad searches. See also
   :attr:`~wazuh.config.Config.bundle_abort_limit`.

Event creation
--------------

:attr:`~wazuh.config.Config.create_obs_sightings`

   Create sightings for observables that do not have indicators based on them

.. _require-indicator:

:attr:`~wazuh.config.Config.require_indicator_for_incidents`

   By default, incidents (and incident response cases) will only be created if
   observables have indicators based on them. These additional settings are
   used to adjust the indicator requirements:

   - :attr:`~wazuh.config.Config.require_indicator_detection`
   - :attr:`~wazuh.config.Config.ignore_revoked_indicators`
   - :attr:`~wazuh.config.Config.indicator_score_threshold`

:attr:`enrich.types <wazuh.enrich_config.EnrichmentConfig.types>`

   Which entites to create as alert context for incidents. By default, all
   supported entities are enabled, which may be noisy (depending on the alerts
   matched).

.. _when-to-run:

When to run
-----------

The CONNECTOR_AUTO setting can be either true (*auto*) or false (*manual*).
Auto is most likely the most preferred choice. However, it is possible to use
:octiu:`playbooks <automation>` to run :octiu:`enrichments
<automation/?h=enrich#enrich-through-connector>` if you have an OpenCTI
enterprice licence. In the example below, the opencti-wazuh-connector is
configured as *manual*, and called through a playbook. The first block is set
to filter on author, so that the connector will only look up entities from
high-quality data sources:

.. image:: images/playbook_1.png

See `this Filigran blog post
<https://blog.filigran.io/introducing-threat-intelligence-automation-and-playbooks-in-opencti-b9e2f9483aba>`_
for an introduction on playbooks.


cti conf. opensearch, api, tlp conf. etc.

- search config
- conf for creating sightings
- for incidents
- incident response

Other considerations
~~~~~~~~~~~~~~~~~~~~

.. toctree::
   :hidden:

   rules_engine

Look at how your OpenCTI :ref:`rules engine <rules-engine>`
is configured in order to avoid any surprises.

.. _config-reference:

Configuration reference
~~~~~~~~~~~~~~~~~~~~~~~

Main configuration
------------------

.. automodule:: wazuh.config
   :members:

OpenSearch configuration
------------------------

.. automodule:: wazuh.opensearch_config
   :members:

Search configuration
--------------------

Look at :ref:`the alert search topic <alert_search>` for details.

.. automodule:: wazuh.search_config
   :members:

Enrichment configuration
------------------------

Look at :ref:`the enrichment topic <enrichment>` for details.

.. autopydantic_settings:: wazuh.enrich_config.EnrichmentConfig
   :settings-show-json-error-strategy: coerce

Wazuh API configuration
-----------------------

Wazuh API is only partially supported.

.. automodule:: wazuh.wazuh_api_config
   :members:
