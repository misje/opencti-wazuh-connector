Environment variables configuration
===================================

In the :ref:`complete configuration reference <config-reference>`, individual
settings are listed as class members in either :attr:`~wazuh.config.Config` or
module-specific configuration classes like
:attr:`~wazuh.opensearch_config.OpenSearchConfig` or
:attr:`~wazuh.enrich_config.EnrichmentConfig`. Each configuration class member
can be referenced as a variable name by capitalising their name, and prefixing
the category name:

.. list-table:: Setting name to env. var. name mapping
   :header-rows: 1

   * - Path
     - Env. var. name
   * - app_url
     - WAZUH_APP_URL
   * - search.ignore_private_addrs
     - WAZUH_SEARCH_IGNORE_PRIVATE_ADDRS
   * - opensearch.password
     - WAZUH_OPENSEARCH_PASSWORD
   * - connector.scope
     - CONNECTOR_SCOPE
   * - opencti.token
     - OPENCTI_TOKEN

At the configuration root level, all environment variables names start with
"WAZUH\_", with the exception of the special categories *opencti* and
*connector*. These two are defined by OpenCTI and passed on to the connector
API. Settings in nested configuration objects, like *search* and *enrich*, are
prefixed with *WAZUH_SEARCH_*, *WAZUH_ENRICH_* etc.

If in doubt, check the *env_prefix* in the configuration class description. You
may also have a look at the :ref:`docker-compose.yml <connector-compose>`
example, which lists all settings with default/example values.

Syntax
------

Values may be specified as they are in most cases. If the value contains
whitespace or special characters, it must be quoted like this:
``"WAZUH_OPENSEARCH_PASSWORD=foo bar baz"``. If in doubt, use quotes.

Special characters
^^^^^^^^^^^^^^^^^^

Dollar signs, **$**, must be escaped by an additional dollar sign, **$$**. This
may be necessary in passphrases that contain these characters, e.g.:

   "WAZUH_PASSWORD=MyPa$word" → "WAZUH_PASSWORD=MyPa$$word"
   "WAZUH_PASSWORD=MyPa$$word" → "WAZUH_PASSWORD=MyPa$$$$word"

Enumerators
^^^^^^^^^^^

Enumerators may be specified in any case, and if they contain hyphens, the
hyphens may be dropped. For instance, if the enumeration value is *IPv4-Addr*,
any of the following values are accepted:

- IPv4-Addr
- ipv4-addr
- Ipv4addr

Date and time
^^^^^^^^^^^^^

Dates/times and relative times can be represented in almost any conceivable
format (and in any langauge if locales are set up correctly), thanks to the
Python library *dateparser*. Examples:

- 2024-01-02 03:04:05
- January 24, 2029 10:00 PM EST
- In two months
- Three weeks ago

Complex data types
^^^^^^^^^^^^^^^^^^

Some settings contain complex data types. Sets or lists of strings or enum
values may be specified as a comma-separated list, e.g.:

- WAZUH_ENRICH_TYPES=Account,Directory,Domain
- "WAZUH_ENRICH_TYPES=Account, Directory, Domain"
- "WAZUH_ENRICH_TYPES=account,directory, domain"

.. note::
  
   All sets of enums accept the special string "all", which will include every
   defined enumerator, if the data type is a *set*.

Other complex data types have their own environment variable-friendly syntax,
documented in the settings reference.
