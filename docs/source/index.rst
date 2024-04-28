OpenCTI–Wazuh connector
===================================================

opencti-wazuh-connector is an `OpenCTI
<https://filigran.io/solutions/open-cti/>`_ :octid:`connector <connectors>`
that lets you look up entities from your cyber threat intelligence database in
your `Wazuh SIEM <https://wazuh.com>`_. It's implemented as an
:octiu:`enrichment connector <enrichment>`, which triggers
automatically (or manually if you want) whenever a new entity
is added to the OpenCTI database.

   .. image:: images/ir_case_example1.png

This connector has several use cases. Perhaps the most obvious one is to
automatically scan your whole SIEM database whenever there is a new indicator
imported in OpenCTI. However, it can also act as a comfortable search
interface, automatically creating sightings for you for every hit.

See :ref:`quick start <quick-start>` FIXME

Introduction
---------------------------------------------------

.. toctree::
   :maxdepth: 2

   introduction
   architecture
   installation
   configuration
   usage
   troubleshooting
   faq
   changelog
   support
   licence
   development
   indices
