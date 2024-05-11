.. _yaml-config:

YAML configuration
==================

If you are not running the connector in docker, you may also load configuration
as YAML (or JSON). The YAML/JSON layout follows `pydantic's
<https://docs.pydantic.dev/latest/>`_ serialisation rules. See :ref:`this
example YAML configuration <yaml-config>` for an example.

The following is a reference for how to configure the connector using a YAML
file. See the :ref:`configuration reference <config-reference>` for details.

.. literalinclude:: yaml-config.yml
   :language: yaml
   :linenos:
