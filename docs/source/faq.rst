.. _faq:

FAQ
===

Look at :ref:`troubleshooting` for answers to typical issues.

Why are entity descriptions never set/updated by the connector?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is deliberate, because the connector never wants to overwrite any
potentially important information in the description field. Determining
whether the entity already exists, and if the description field is empty,
would require a lot of API calls.

There are a few exceptions, like when creating Network Address :term:`SCOs
<SCO>` during :ref:`enrichment <enrichment>`. Without a description, which
contains a textual representation of the source, destination and protocols,
the information in these objects would be hard to grasp.

Why can I not search for Software SCOs?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are no alerts that contain enough information about software installation
(or removal), so this must be done with the Wazuh API (which is currently only
partially implemented). This is on the roadmap.

Why is this connector not part of the OpenCTI connectors GitHub project
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It probably could be, but the benefits of having a separate project will full
access gives the developers the following benefits:

- Full control over issues, issue templates, milestones etc., not shared across
  oodles of sub projects (connectors)
- Full automation access for tests and documentation building/publishing
- The ability to use GitHub pages for documentation
