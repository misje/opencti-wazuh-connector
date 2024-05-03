.. _common-connector-settings:

Common connector settings
=========================

The following setting sare common for all OpenCTI connectors

Required
~~~~~~~~

OPENCTI_URL
-----------

This is the URL to the OpenCTI server. Connectors are typically run in the
same docker-compose file as the server. This lets you refer to this URL with
the variable **${OPENCTI_BASE_URL}**.

OPENCTI_TOKEN
-------------

This token is used for the connector to access OpenCTI's API. See :ref:`create
OpenCTI user <create-opencti-user>` for how to create a token. Please refrain
from using an admin token (like ${OPENCTI_ADMIN_TOKEN}, for reasons described
in the aforementioned chapter.

CONNECTOR_ID
-------------

This is just a unique identifier for each token. It can technically be
anything, but it *should* be UUID. On Linux, with *uuidgen* installed, you may
generate a UUID simply by running ``uuidgen``.

CONNECTOR_NAME
--------------

Simply the connector name. Please use "Wazuh".


CONNECTOR_SCOPE
---------------

This specifies all entities that the connector should be made available for
enrichment. If an entity is not lsted here, the connector will not show up as
an option when clicking on the enrichment button in OpenCTI. See
:ref:`supported entities <supported-entities>` for supported choices.

CONNECTOR_AUTO
--------------

Whether to run the connector automatically whenever an entity in
*CONNECTOR_SCOPE* is created, or just manually. See :ref:`when to run
<when-to-run>` for details.


Optional
~~~~~~~~

CONNECTOR_LOG_LEVEL
-------------------

Set the log level to *warning* or *error* under normal use. Use *debug* when
troubleshooting and gathering info for an issue.

CONNECTOR_EXPOSE_METRICS
------------------------

TODO
