.. _rules-engine:

Rules engine
============

OpenCTI's :octia:`rules engine <reasoning>` provides a number
of ways to create entities and relationships (among other
things) automatically according to predefined rules. This
topic describes how certain rules may affect this connector of
vice versa.

Alerting
~~~~~~~~

.. _rule-sightings-propagations:

Sightings propagation from observable
-------------------------------------

This connector does not create sightings of indicators, and
laves this job to this rule. Using the rule for this job
instead of creating the sighting within the connector allows
you to easily revert and remove indicator sightings simply by
turning the rule off.

Raise incident basd on sightings
--------------------------------

This rule creates incidents if an indicator is sighted in an
entity, and then creates a "targets" relationship between the
incident and the entity. This connector does not create
sightings of indicators, but these can be automaticallycreated
by using the rule :ref:`sightings propagation from observable
<rule-sightings-propagations>`. However, enabling this rule
may create a huge amount of incidents if your other (import)
connectors create a lot of (indicator) sightings. Using this
rule is not recommended, because this connector will create
the incidents directly. This gives the connector more control
over when to create incidents, and what to include in the
incident as context (see :ref:`enrichment`). The following
settings determines when to create incidents:

- :attr:`~wazuh.config.Config.require_indicator_for_incidents`
- :attr:`~wazuh.config.Config.require_indicator_detection`
- :attr:`~wazuh.config.Config.ignore_revoked_indicators`
- :attr:`~wazuh.config.Config.indicator_score_threshold`
