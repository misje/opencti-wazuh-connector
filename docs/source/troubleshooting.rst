.. _troubleshooting:

Troubleshooting
===============

See the :ref:`FAQ` for topics that are not related to troubleshooting.

Common issues
~~~~~~~~~~~~~

"Indicator is not based on any observables"
-------------------------------------------

When enriching an Indicator, the indicator needs to have a "based-on"
relationship on an observable. See :ref:`supported entities
<supported-entities>` for more information.

"Entity ignored because TLP not allowed"
----------------------------------------

Adjust your :attr:`~wazuh.config.Config.max_tlp` if this is an issue.

"Ignoring entity because it was created by […]"
-----------------------------------------------

This is a result of enabling the setting
:attr:`~wazuh.config.Config.ignore_own_entities`. Please look at
:attr:`~wazuh.config.Config.label_ignore_list` for a better alternative.

"Ignoring entity because it has the following label(s) […]"
-----------------------------------------------------------

This is caused by :attr:`~wazuh.config.Config.label_ignore_list`. If you want
to enrich the entity, simply remove the label and re-enrich.

.. _no-sightings:

"Observable has no indicators"
------------------------------

This happens when an indicator is required in order to create sightings
(:attr:`~wazuh.config.Config.create_obs_sightings` is set to false).


"[…] has no queryable data"
---------------------------

This happens when the searched entity does not have any compatible metadata,
e.g.

- The entity is an Artifact and does not contain any hashes (there is no other
  useful metadata to search for)
- The entity is a File, has no hashes, and the search settings disallows
  searching for name
- Search settings disallow use of regular expressions, and this kind of query
  is required in order to perform a search
- The IPv4/IPv6 :term:`SCO` contains a private IP address, and the settings
  says to ignore these

Set the :ref:`log level <enable-debug-logs>` to at least *info* and
:ref:`inspect the logs <search-logs>` if you want to understand why an entity
has no queryable data.

"No hits found"
---------------

This means that the search was successful, but no alerts were found in
OpenSearch. This may not be an issue at all. However, if you expected to find
something, check the following:

- Ensure that you're searching the right :attr:`indices
  <wazuh.opensearch_config.OpenSearchConfig.index>`, and that your
  :attr:`OpenSearch user <wazuh.opensearch_config.OpenSearchConfig.username>`
  has the correct permissions to access these indices (which shouldn't be a
  problem if you assigned it the *readall* backend role as described :ref:`here
  <create-opensearch-user>`).
- Ensure that your :ref:`search filters <search-filters>` are not limiting your
  results.
- Depending on the type of entity being enriched, ensure that your
  :attr:`search settings <wazuh.search_config.SearchConfig>` allow for the kind
  of search that you want.

"Too many hits […]"
-------------------

The OpenSearch query resulted in too many hits and the
:attr:`~wazuh.config.Config.hits_abort_limit` safeguard aborted further
processing. This indicates a poor search or that this setting is set too low.

"Bundle is too large […]"
-------------------------

This is a result of either too many search hits or more likely, too many
entities created during :ref:`enrichment <Enrichment>`. The
:attr:`~wazuh.config.Config.bundle_abort_limit` safeguard stops further
processing. Adjust this limit, or consider adjusting :attr:`which entities to
enrich <wazuh.enrich_config.EnrichmentConfig.types>`.

"Not creating incident because entity is a vulnerability, […]"
------------------------------------------------------------------

Typical causes are

- :attr:`~wazuh.config.Config.vulnerability_incident_cvss3_score_threshold` is
  set too low
- :attr:`~wazuh.config.Config.vulnerability_incident_active_only` is enabled
  and the vulnerability is no longer active in any of the systems (within the
  search constraints, like :attr:`search.limit
  <wazuh.opensearch_config.OpenSearchConfig.limit>`)
- The vulnerability does not have a CVSS3 score, nor a severity, defined and a
  CVSS3 score could not be extracted from the search hits
- The vulnerability does not have a CVSS3 score defined, but it has a severity,
  but the score translated from the severity is below
  :attr:`~wazuh.config.Config.vulnerability_incident_cvss3_score_threshold`

No sightings are created
------------------------

See :ref:`"Observable has no indicators" <no-sightings>`.

No incidents are created
------------------------

Incidents are only created when observables have indicators based on them,
unless :attr:`~wazuh.config.Config.require_indicator_for_incidents` is set to
false. For vulnerabilities,
:attr:`~wazuh.config.Config.vulnerability_incident_cvss3_score_threshold` must
be set for incidents to be created when a vulnerability is sighted. See
:ref:`require indicators <require-indicator>` for more information on which
settings influence incident creation.

Incident response cases are not created
---------------------------------------

Enable :attr:`~wazuh.config.Config.create_incident_response` (it is enabled by
default).

Two User-Account SCOs are created for the same user
---------------------------------------------------

During enrichment, two User-Account :term:`SCOs <SCO>` may be created, possibly
for the same user. One will contain the account name only, and the other the
user ID only. When this happens, the SCOs are created from individual alerts,
and the connector cannot be sure that they are related. You'll have to merge
these object yourself, unfortunately.

Network Traffic SCOs are always displayed as "Unknown"
------------------------------------------------------

This happens when the destination port (dst_port) is not set, which is very
often the case, bacause many alerts do not contain this information. Sadly,
without the dst_port, OpenCTI has decided to just use "Unknown" instead of
using other available information, like protocols.

.. _enable-debug-logs:

Enable debug logs
~~~~~~~~~~~~~~~~~

If you're running the connector in docker (the only officially supported way),
ensure that the following environment variable is present and configured as
shown in your *docker-compose.yml* file under the section *environment:*

- **CONNECTOR_LOG_LEVEL=debug**

.. _search-logs:

Search the logs
~~~~~~~~~~~~~~~

If you're using docker-compose, you can get a continuous log by running
``docker compose logs -f --tail=0 connector-wazuh``, and adjust the *tail*
argument to retrieve more historical log data.

"docker: 'compose' is not a docker command."
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Install the package **docker-compose-v2**. Alternatively, use `docker-compose`
instead of `docker compose`.

Known bugs
~~~~~~~~~~~~

Registry values are not enriched
--------------------------------

This is due to :octigh:`an OpenCTI issue <opencti/issues/2574>`.

The *Matches* table in the alert note is broken
-----------------------------------------------

This happens when data from the alert contains text interpreted as valid
Markdown. Markdown will be escaped in the future.

External references only appear after a second enrichment
---------------------------------------------------------

This may be an OpenCTI bug, but it has not been confirmed yet.

Docker compose fails with "Not supported URL scheme http+docker"
----------------------------------------------------------------

If you get the exception "docker.errors.DockerException: Error while fetching
server API version: Not supported URL scheme http+docker", then you may have
installed the python library "requests" using pip, and the installed version is
incompatible with your system's version of `docker-compose`. Remove the
package: `pip uninstall requests`.

Connector state is always "null"
--------------------------------

The connector has a state, which is either running or not, but it is not
available in the connector web interface for technical reasons.
