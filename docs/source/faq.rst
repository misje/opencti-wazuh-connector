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
