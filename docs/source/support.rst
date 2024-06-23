.. _support:

Support and community
=====================

opencti-wazuh-connector is provided to the security community as open source,
completely free of charge. There is no support provided, but the maintainers
are very interested in feedback that improves the project. This requires
effort from the reporter: Provide sufficient issue descriptions, necessary
files to reproduce the issue, and logs. Please follow the guidelines and spend
time writing good support requests, and you're more likely to be heard.

The project is currently in no need of a dedicated communication forum. If you
are in need of a help, :ref:`file an issue <issue>`. If you do not have a
GitHub user account, feel free to reach out to one of the maintainers on Slack
in either the Wazuh or OpenCTI communities (search for their names).

.. _versions:

Versions and compatibility
--------------------------

The table below lists for what version of OpenCTI a connector version is
built/tested against in a release, and when a known incompatibility is
reported. Little effort is made testing older versions of the connector against
newer version of OpenCTI or vice versa.

.. list-table:: OpenCTI compatibility overview
   :header-rows: 1

   * - Connector v.
     - OpenCTI v. from
     - OpenCTI v. to
   * - 0.1.0
     - 6.0.10
     - ?
   * - 0.2.0
     - 6.1.1
     - ?
   * - 0.2.1
     - 6.1.4
     - ?
   * - 0.3.0
     - 6.1.10
     - ?
   * - 0.3.1
     - 6.1.12
     - ?

See :ref:`versioning <versioning>` for an overview of how version numbers and
docker tags are used.

The connector may work just fine on an older or newer OpenCTI instance. You may
try to replace the pycti version in *src/requirements.txt* and build the image
yourself, while waiting for a new release or if you want to keep a connector
release version, but use an old pycti version.

However, since the OpenCTI API and SDK does not follow semantic versioning for
compatibilty, the connector may break at any time when even just the patch
version does not match. This is why the compatibilty table above does not
explicitly set a final supported OpenCTI version number unless an
incompatibility is known.

.. _issue:

Filing issues
-------------

First of all, please read through :ref:`troubleshooting` and :ref:`faq`.  Then
look at already :github:`reported issues <issues>` in case your problem is
known, and provide follow-up details, if necessary.

If you still have an issue with the connector, :github:`file an issue
<issues/new>`, and follow the issue template. In order to help you, follow as
many of the following steps as possible (this assumes a docker setup):

#. :ref:`Enable debug logs <enable-debug-logs>`
#. Restart the connector and print the log output: ``docker compose up -d
   --build && docker compose logs -f --tail=0 connector-wazuh worker``
#. Reproduce the issue, typically be re-enriching the entity

   - Remember to remove the *wazuh_ignore* label if the connector ignores your
     entity on subsequent enrichments
#. Copy all the connector logs up to and including the failure, and be sure to
   include the worker log if the fault is a MISSING REFERENCE error.
#. Include your connector configuration, but **remember to remove all secrets
   and sensible information, like URLs, usernames and passwords**. Use a line
   like this to strip sensible information: ``sed -r
   '/TOKEN|USERNAME|PASSWORD|URL/c\(REDACTED)' docker-compose.yml >
   /tmp/docker-compose.yml``.
#. If possible, include relevant Wazuh alerts

Ideally, try to reproduce the issue in a fresh OpenCTI installation. You can
easily fire one up by looking at :ref:`OpenCTI demo <opencti-docker>`. Some
MISSING REFERENCE ERROR issues are OpenCTI bugs.

Getting help without a GitHub account
-------------------------------------

If you need to get in touch and if you're not a member of GitHub, you may try
to get in touch with the maintainers on either Wazuh's or OpenCTI's Slack
channels. You're expected to make the same level of effort in providing
details of your issue as if were to create a GitHub issue. If you do not get a
response, be patient. Maintainers only visit the Slack channels sporadically,
and if you fail to make an effort in your initial contact, you may be ignored.

Paid support
------------

Paid support is not available. If you are interested in this, contact the
maintainers, and this service may be considered.
