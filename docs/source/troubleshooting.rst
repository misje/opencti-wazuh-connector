.. _troubleshooting:

Troubleshooting
===============

.. _enable-debug-logs:

Enable debug logs
~~~~~~~~~~~~~~~~~

If you're running the connector in docker (the only officially supported way),
ensure that the following environment variable is present and configured as
shown in your *docker-compose.yml* file under the section *environment:*

- **CONNECTOR_LOG_LEVEL=debug**

Known issues
~~~~~~~~~~~~


Registry values are not enriched
--------------------------------

This is due to :octigh:`an OpenCTI issue <opencti/issues/2574>`.
