.. _alert_search:

Alert search
===================================================

Before the connector can produce any meaningful information to import in
OpenCTI, it has to look up entity metadata in Wazuh's OpenSearch database. A
typicaly use case in an automated setup, is to look up every new :stix:`File
<#_99bl2dibcztv>` and :stix:`Artifact <#_4jegwl6ojbes>` hash :term:`IoCs <IoC>`
imported into OpenCTI. Other common IoCs are :stix:`domain names
<#_prhhksbxbg87>` and :stix:`IPv4 <#_ki1ufj1ku8s0>`/:stix:`IPv6
<#_oeggeryskriq>` addresses. The connector has support for looking up all of
these, along with many other observables.

It is also possible to look up alerts using less common metadata, like
filenames, directory paths and process command lines. This can be helpful in an
investigation, if you want to see where files, whose contents varies, has
spread across systems, or where a process may have been run. This essentially
makes OpenCTI into a search interface for OpenSearch, allowing you to search
for alerts without having to craft complicated :term:`DSL` queries yourself. Be
sure to read the usage documentation below before doing so, and beware that
"simple" searches may result in a lot of results (sightings), which in turn may
create incidents depending your configuration.

Configuration
~~~~~~~~~~~~~

Use CONNECTOR_SCOPE to select which entities to search for. Use the various
settings in :attr:`~wazuh.search_config.SearchConfig` to determine how searches
are performed.

Observables that have been created by the connector through :ref:`enrichment
<enrichment>` are not looked up by default (determined by
:attr:`~wazuh.config.Config.label_ignore_list` and
:attr:`~wazuh.config.Config.enrich_labels`). In order to look up these
entities, simply remove the *WAZUH_IGNORE* label and run the enrichment again.

.. _supported-entities:

Supported entities
~~~~~~~~~~~~~~~~~~

The function documentation below describes how the various supported entities
are looked up. Most observables, along with vulnerabilities and indicators are
supported.

Indicators are special: **There is no direct support for searching
indicators**, but they can be useful to include in the connector scope in the
following situation:

1. An observable is created in the OpenCTI platform. It is automatically
   enriched by the connector, but because the configuration requires
   observables to have indicators based on them (see
   :attr:`~wazuh.config.Config.require_indicator_for_incidents`
   , :attr:`~wazuh.config.Config.require_indicator_detection`
   , :attr:`~wazuh.config.Config.ignore_revoked_indicators` and
   :attr:`~wazuh.config.Config.indicator_score_threshold`), sightings/incidents
   are not created.
2. An indicator is later created with a relationship indicating that it is
   "based on" an observable. The enrichment of the indicator will run on the
   observable that it is based on, just as if the observable was enriched
   directly. The search will now produce events, because of the new indicator
   relationship.

Even if the indicator and the relationship are created or imported into OpenCTI
at the same time as the observable, this information is not available at the
time the connector is told to enrich the observable automatically. The separate
enrichment of the indicator is therefore necessary.

.. note:: The indicator pattern is not used at all.
.. note:: If the indicator is based on more than one observable, only the first
          relationship is taked into    consideration.

.. autoclass:: wazuh.search::AlertSearcher.query_file
   :members:
   :noindex:
.. autoclass:: wazuh.search::AlertSearcher.query_addr
   :members:
   :noindex:
.. autoclass:: wazuh.search::AlertSearcher.query_mac
   :members:
   :noindex:
.. autoclass:: wazuh.search::AlertSearcher.query_traffic
   :members:
   :noindex:
.. autoclass:: wazuh.search::AlertSearcher.query_email
   :members:
   :noindex:
.. autoclass:: wazuh.search::AlertSearcher.query_domain
   :members:
   :noindex:
.. autoclass:: wazuh.search::AlertSearcher.query_url
   :members:
   :noindex:
.. autoclass:: wazuh.search::AlertSearcher.query_directory
   :members:
   :noindex:
.. autoclass:: wazuh.search::AlertSearcher.query_reg_key
   :members:
   :noindex:
.. autoclass:: wazuh.search::AlertSearcher.query_reg_value
   :members:
   :noindex:
.. autoclass:: wazuh.search::AlertSearcher.query_process
   :members:
   :noindex:
.. autoclass:: wazuh.search::AlertSearcher.query_vulnerability
   :members:
   :noindex:
.. autoclass:: wazuh.search::AlertSearcher.query_account
   :members:
   :noindex:
.. autoclass:: wazuh.search::AlertSearcher.query_user_agent
   :members:
   :noindex:

.. toctree::
   :maxdepth: 2
