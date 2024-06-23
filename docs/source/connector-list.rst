.. _connector-list:

List of useful connectors
=========================

This is a list of connectors that help kick-start your OpenCTI with threat
intel and useful enrichment tools.

**$** means that the connector requires a paid subscription. Those that are not
marked with *$* will most often require an account, and will impose limits on
your requests. Whether the limits is an issue to you, really depends on your
ingestion and use.

.. list-table:: OpenCTI connectors
   :header-rows: 1

   * - Name
     - Type
     - Limitations
     - Description
   * - abuse-ssl
     - external import
     - 
     - 
   * - abuseipdb-ipblacklist
     - external import
     - 
     - 
   * - alienvault
     - external import
     - 
     - 
   * - connector-cape
     - external import
     - Requires own instance(?)
     - 
   * - chapsvision
     - external import
     - $
     - 
   * - cisa-known-exploited-vulnerabilities:
     - external import
     - 
     - Imports a static file. Useful.
   * - citalid
     - external import
     - $
     - 
   * - cluster25
     - external import
     - $
     - 
   * - comlaude
     - external import
     - $
     - 
   * - crits
     - external import
     - 
     - Uninteresting(?)
   * - crowdstrike
     - external import
     - $
     - 
   * - crtsh
     - external import
     - 
     - Uninteresting(?)
   * - cuckoo
     - external import
     - Requires own instance(?)
     - 
   * - cve
     - external import
     - 
     - Essential
   * - cmapaign-collection
     - external import
     - ?
     - ?
   * - cybersixgill
     - external import
     - $
     - 
   * - disarm-framework
     - external import
     - 
     - Imports static file. Useful
   * - eset
     - external import
     - $
     - 
   * - feedly
     - external import
     - $
     - 
   * - flashpoint
     - external import
     - $
     - 
   * - google-drive
     - external import
     - 
     - Uninteresting(?)
   * - intel471
     - external import
     - $
     - 
   * - intelfinder
     - external import
     - $
     - 
   * - ironnet
     - external import
     - $
     - 
   * - kapersky
     - external import
     - $
     - 
   * - lastinfosec
     - external import
     - 
     - 
   * - malpedia
     - external import
     - Not open for registrations [#f2]_
     - 
   * - maltiverse
     - external import
     - 
     - 
   * - malware-bazaar-recent-additions
     - external import
     - 
     - Downloads lots of malware samples. Uninteresting.
   * - mandiant
     - external import
     - Registration only for cyber security businesses
     - 
   * - misp-feed
     - external import
     - 
     - A generic connector [#f1]_
   * - misp
     - external import
     - No known MISP feeds to import from(?)
     - 
   * - mitre
     - external import
     - 
     - Imports a static file. Essential.
   * - mwdb
     - external import
     - Requires own instance(?)
     - 
   * - obstracts
     - external import
     - 
     - Uninteresting(?)
   * - opencsam
     - external import
     - Requires own instance(?)
     - 
   * - opencti
     - external import
     - 
     - OpenCTI's own static sector, geography and company datasets
   * - orange-cberdefense
     - external import
     - $
     - 
   * - phishunt
     - external import
     - 
     - Barely no data?
   * - recordedfuture-feeds
     - external import
     - $
     - 
   * - recordedfuture-notes
     - external import
     - $
     - 
   * - restore-files
     - external import
     - 
     - Uninteresting(?)
   * - riskiq
     - external import
     - $
     - 
   * - rst-report-hub
     - external import
     - $
     - 
   * - rst-threat-feed
     - external import
     - $
     - 
   * - sekoia
     - external import
     - $
     - 
   * - sentinelone-threats
     - external import
     - $
     - 
   * - siemrules
     - external import
     - Not open for registrations
     - 
   * - silobreaker
     - external import
     - $
     - 
   * - socprime
     - external import
     - $
     - 
   * - stixify
     - external import
     - 
     - Uninteresting(?)
   * - stopforumspam
     - external import
     - 
     - Uninteresting(?)
   * - taxii2
     - external import
     - 
     - Uninteresting(?)
   * - thehive
     - external import
     - Requires own instance(?)
     - 
   * - threatfox
     - external import
     - 
     - Covered by misp-feed:threatfox?
   * - threatmatch
     - external import
     - $
     - 
   * - tweetfeed
     - external import
     - Doesn't work
     - 
   * - urlhaus-recent-payloads
     - external import
     - 
     - Uninteresting(?)
   * - urlhaus
     - external import
     - 
     - 
   * - urlscan
     - external import
     - ?
     - ?
   * - valhalla
     - external import
     - ?
     - ?
   * - virustotal-livehunt-notifications
     - external import
     - 
     - Uninteresting(?)
   * - vulmatch
     - external import
     - $
     - 
   * - vxvault
     - external import
     - Not maintained?
     - 
   * - zerofox
     - external import
     - $
     - 
   * - abuseipdb
     - internal enrichment
     - 
     - Useful
   * - abuseipdb-ipblacklist
     - internal enrichment
     - Quickly uses up free quota if automatic
     - 
   * - anyrun-task 
     - internal enrichment
     - ?
     - ?
   * - attribution-tools
     - internal enrichment
     - ?
     - ?
   * - cape-sandbox
     - internal enrichment
     - Requires own instance(?)
     - 
   * - crowdsec
     - internal enrichment
     - 
     - Useful(?)
   * - dnstwist
     - internal enrichment
     - ?
     - ?
   * - domaintools
     - internal enrichment
     - $
     - 
   * - google-dns
     - internal enrichment
     - 
     - Useful
   * - greynoise
     - internal enrichment
     - $ (connector does not use community API)
     - 
   * - hatching-triage-sandbox
     - internal enrichment
     - $
     - 
   * - hostio
     - internal enrichment
     - $
     - 
   * - hybrid-analysis-sandbox
     - internal enrichment
     - 
     - Useful
   * - hygiene
     - internal enrichment
     - 
     - Useful
   * - import-external-reference
     - internal enrichment
     - 
     - Uninteresting(?)
   * - intezer-sandbox
     - internal enrichment
     - $(?)
     - 
   * - ipinfo
     - internal enrichment
     - 
     - Useful
   * - ipqs
     - internal enrichment
     - 
     - Useful(?)
   * - ivre
     - internal enrichment
     - Requires own instance?
     - ?
   * - joe-sandbox
     - internal enrichment
     - 
     - Useful
   * - lastinfosec-enrichment
     - internal enrichment
     - Doesn't work?
     - 
   * - malbeacon
     - internal enrichment
     - $
     - 
   * - orion-malware
     - internal enrichment
     - $?
     - 
   * - recordedfuture-enrichment
     - internal enrichment
     - $
     - 
   * - shodan-internetdb
     - internal enrichment
     - 
     - Useful
   * - shodan
     - internal enrichment
     - $
     - 
   * - tagger
     - internal enrichment
     - 
     - Uninteresting(?)
   * - unpac-me
     - internal enrichment
     - $
     - 
   * - virustotal-downloader
     - internal enrichment
     - 
     - Uninteresting(?)
   * - virustotal
     - internal enrichment
     - 
     - Useful
   * - vmray-analyzer
     - internal enrichment
     - $
     - 
   * - yara
     - internal enrichment
     - 
     - 

.. note::

   Do not use this as an authoritative soure of any means. It's just note to
   help you avoid wasting time looking up each and every connector, only to
   realise that the services needed are closed for registration, costly, or
   irrelevant (for most users).

.. note::

   OpenCTI's connector development is rapid. This list may be out of date.
   Please help keeping it up to date by :ref:`filing an issue <issue>`.

.. rubric:: Footnotes

.. [#f1] This connector must be set up to import from specific feeds. Known
   useful feeds:

   - threatfox
   - botvrij

.. [#f2] The connector still works in a limited capacity witout a token. For
   instance, it will still download :term:`YARA` :term:`IoCs <IoC>`
