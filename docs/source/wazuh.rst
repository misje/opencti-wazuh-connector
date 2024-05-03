.. _wazuh:

Wazuh
=====

Wazuh is an open-source :term:`SIEM`. Read more about the tool on `its website
<https://wazuh.com/>`_. You are expected to be familiar with Wazuh and have it
deployed, otherwise this connector will not be very useful to you. However, if
you are coming from the :term:`CTI` world and want to test the connector on a
demo instance of Wazuh with test data, have a look at the :ref:`full demo
<full-demo-compose>`.

In order to fully understand how the connector works, it is worth knowing at
least a little bit about how Wazuh works.

.. _agent:

Agent
~~~~~

Each device monitored by Wazuh is called an agent. Agents have a three-digit
identifier. Wazuh itself will also be listed as an agent, with ID 000, and will
not be considered as an agent by the connector, but its own identity
(:attr:`~wazuh.config.Config.system_name`). If
:attr:`~wazuh.config.Config.agents_as_systems` is true, each agent will be its
own identity in OpenCTI.

Wazuh and its agents are represented as :octiu:`systems
<exploring-entities/?h=system#systems>` (a type of identity) in OpenCTI, and
are used as targets in :octiu:`sightings <exploring-events/#sightings>`.

Alert
~~~~~

An alert is an event, typically originating from a log, that Wazuh's rules
consider worthy of logging. It need not be an important event, despite the name
*alert*. Alerts are classified with a :wazuh:`rule level
<ruleset/rules-classification.html>`, ranging from 1 to 15 (0 are never
logged).

The following is an example alert:

.. code:: json
   :number-lines:

   {
      "_index": "wazuh-alerts-4.x-sample",
      "_id": "QeizKY8BtDMkMQlwZ138",
      "_score": 1.8809273,
      "_source": {
         "predecoder": {
         "hostname": "wazuh-manager",
         "program_name": "sshd",
         "timestamp": "Apr 27 18:49:51"
         },
         "cluster": {
         "node": "wazuh-manager",
         "name": "wazuh-cluster"
         },
         "agent": {
         "ip": "145.80.240.15",
         "name": "Amazon",
         "id": "002"
         },
         "manager": {
         "name": "wazuh-manager"
         },
         "data": {
         "srcuser": "ec2-user",
         "srcip": "141.98.81.37",
         "srcport": "3527"
         },
         "@sampledata": true,
         "rule": {
         "firedtimes": 3,
         "level": 5,
         "pci_dss": [
            "10.2.4",
            "10.2.5",
            "10.6.1"
         ],
         "hipaa": [
            "164.312.b"
         ],
         "tsc": [
            "CC1.4"
         ],
         "description": "sshd: Attempt to login using a non-existent user",
         "groups": [
            "syslog",
            "sshd",
            "invalid_login",
            "authentication_failed"
         ],
         "id": 5710,
         "nist_800_53": [
            "AU.14",
            "AC.7",
            "AU.6"
         ],
         "gpg13": [
            "7.1"
         ],
         "gdpr": [
            "IV_35.7.d",
            "IV_32.2"
         ]
         },
         "decoder": {
         "parent": "sshd",
         "name": "sshd"
         },
         "full_log": "Apr 27 18:49:51 wazuh-manager sshd[10022]: Invalid user ec2-user from ec2-user from 141.98.81.37 port 3527 ssh2",
         "input": {
         "type": "log"
         },
         "@timestamp": "2024-04-27T18:49:51.048Z",
         "location": "/var/log/secure",
         "id": "1580123327.49031",
         "GeoLocation": {
         "city_name": "Berlin",
         "country_name": "Germany",
         "location": {
            "lon": 13.411,
            "lat": 52.524
         },
         "region_name": "Berlin"
         },
         "timestamp": "2024-04-27T18:49:51.048+0000"
      }
   }

Alerts do not follow a strict schema/model, but the same fields are reused in
many decoders. It is also possible to write custom decoders for Wazuh, where
fields can be customised by the author.

This connector makes an effort trying to search all possible relevant fields,
but given the lack of a schema/model, **false positives are possible**, as well
as **false negatives** (alerts missed in searches). Please :ref:`report
<issue>` false positives and false negatives.

OpenSearch
~~~~~~~~~~

OpenSearch is the main database used by Wazuh, storing all alerts. The
connector relies completely on this database for querying and enriching data.
Wazuh also stores state and other information, such as installed software and
active connections, in other databases, only available through the *Wazuh API*.
Querying this API is still under development.

Your Wazuh installation may use Elastic instead of OpenSearch. The API should
however be compatible, even if there is no official support for this.
