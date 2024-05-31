from pydantic import (
    Field,
    field_validator,
)
from pydantic_settings import SettingsConfigDict
from .utils import comma_string_to_set
from .config_base import ConfigBase, FuzzyEnum

# TODO: test if a member has a union (e.g. TLPLiteral|str), and doesn't have a
# validator that changes the type, that the resulting object has the most
# strong type. If so, add these unions and remove "type:ignore" comments from
# test code


class FilenameBehaviour(FuzzyEnum):
    CreateDir = "create-dir"
    """
    Create a :stix:`Directory SCO <#_lyvpga5hlw52>` *parent_directory_ref* when
    creating a File

    When this option is enabled, a Directory is created and referenced as a
    parent directory whenever a :stix:`File SCO <#_99bl2dibcztv>` is created.
    """
    RemovePath = "remove-path"
    """
    Remove path from :stix:`File SCOs <#_99bl2dibcztv>` and add FIXME
    """
    # FIXME: implement:
    # CreateContains = "create-contains"


class EnrichmentConfig(ConfigBase):
    """
    This configuration dictates how the connector should enrich incidents with
    observables and other entities
    """

    model_config = SettingsConfigDict(
        env_prefix="WAZUH_ENRICH_", validate_assignment=True
    )

    class EntityType(FuzzyEnum):
        """
        Entity types to enrich

        See :doc:`enrichment` for details.
        """

        Account = "user-account"
        """
        Enrich :stix:`user accounts <#_azo70vgj1vm2>`

        User accounts will be created from all fields that contain usernames
        and/or user IDs / SIDs. The user ID may be an e-mail, for instance in
        alerts from Office 365 and :term:`GCP`.

        The following properties may be set:

        - account_login
        - user_id
        """
        AttackPattern = "attack-pattern"
        """
        Enrich `MITRE <https://attack.mitre.org/>`_ :stix:`attack patterns <#_axjijf603msy>`

        Create and reference MITRE TTPs from rule.mitre.id. Only the MITRE ID is
        used, so unless another connector like :ghconnector:`mitre
        <external-import/mitre>` is used, the attack patterns created by
        opencti-wazuh will be empty, containing only the MITRE ID.

        The following properties are set:

        - Name
        - External ID
        """
        Directory = "directory"
        """
        Enrich :stix:`directories <#_lyvpga5hlw52>` from paths

        The fields used are fields known to contain only paths, without any
        filenames. Directory objects are still created as parent directory
        references whenever File objects are created. See :attr:`File`.

        The following properties are set:

        - path
        """
        Domain = "domain-name"
        """
        Enrich :stix:`domain names <#_prhhksbxbg87>`

        Since it is often hard to distinguish hostnames from domain names, no
        hostname :term:`SCOs <sco>` (OpenCTI's custom SCO) are created.
        Hostnames may be created as domain names.

        The following properties are set:

        - value
        """
        EMailAddr = "email-addr"
        """
        Enrich :stix:`e-mail addresses <#_wmenahkvqmgj>`

        The following properties are set:

        - value
        """
        File = "file"
        """
        Enrich :stix:`files <#_99bl2dibcztv>`

        The following properties may be set:

        - name (always)
        - MD5
        - SHA1
        - SHA256
        - atime
        - ctime
        - mtime
        - size
        """
        IPv4Address = "ipv4-addr"
        """
        Enrich :stix:`IPv4 <#_ki1ufj1ku8s0>` addresses

        The following properties are set:

        - value
        """
        IPv6Address = "ipv6-addr"
        """
        Enrich :stix:`IPv6 <#_oeggeryskriq>` addresses

        The following properties are set:

        - value
        """
        MAC = "mac-addr"
        """
        Enrich :stix:`MAC addresses <#_f92nr9plf58y>`

        The format used is lower-case colon-delimited hexadecimal characters
        (EUI-48, as per the :term:`STIX` standard).

        The following properties are set:

        - value
        """
        NetworkTraffic = "network-traffic"
        """
        Enrich :stix:`network traffic <#_rgnc3w40xy>`

        As opposed to when searching for network traffic :term:`SCOs <SCO>`,
        enrichment will only extract network traffic from fields known to
        contain network traffic logs. Searching is perfomed much more broadly.
        Therefore, there is (currently) no support for domain names and MAC
        addreses as source/destination.

        The following properties may be set:

        - src_ref (IPv4-Addr/IPv6-Addr)
        - dst_ref (IPv4-Addr/IPv6-Addr)
        - src_port
        - dst_port
        - protocols
        - description

        At least two of src_ref, dst_ref, src_port and dst_port must be
        present for the SCO to be created. protocols may be inferred from the
        event.

        .. note:: Unfortunately, OpenCTI has decided to focus on dst_port when
                  displaying the network traffic SCO in graphs, or "Unknown"
                  if the dst_port is not set. In many alerts, the destination
                  port is not known. In order to provide a more helpful way to
                  understand the SCO, the connector writes a connetion string
                  in the description, like "ipv4:ssh 10.20.30.40 →
                  10.20.30.42:?".
        """
        Process = "process"
        """
        Enrich :stix:`processes <#_hpppnm86a1jm>`

        Due to a limitation set by OpenCTI (not the :term:`STIX` standard),
        process :term:`SCOs <SCO>` cannot be created unless *command_line* can
        be populated (even if there is a lot of other useful information). The
        log will inform about this (log level *info*) when this happens.

        sysmon
        ------

        The following properties may be set (most are typically available):

        - pid
        - cwd
        - command_line
        - creator (User-Account with account_login and/or user_id)
        - image (File with filename (and SHA256))
        - parent_ref (Process with similar information about the parent
          process)

        auditd
        ------

        The following properties may be set (most are typically available):
    
        - pid
        - command_line
        - creator (User-Account with user_id (auid))
        - image (File with filename)

        ppid (parent PID) is available, but cannot be referenced because it
        would imply using parent_ref and another Process object, and there is
        no command_line information for the parent.
        """
        RegistryKey = "windows-registry-key"
        """
        Enrich :stix:`Windows registry keys <#_luvw8wjlfo3y>`

        The following properties may be set:

        - key (always)
        - values

        .. note:: Due to the OpenCTI bug :octigh:`#2574
                  <opencti/issues/2574>`, the values are currently not
                  imported.
        """
        Software = "software"
        """
        Enrich :stix:`software <#_7rkyhtkdthok>`

        Currently, software :term:`SCOs <SCO>` are only enriched from
        vulnerability alerts.

        The following properties may be set:

        - name (always)
        - version
        """
        Tool = "tool"
        """
        Enrich :stix:`tool <#_z4voa9ndw8v>` :term:`SDOs <SDO>`

        Tools are enriched by looking up names of all tools found in OpenCTI
        (fetched using the API when the connector starts) in fields containing
        command lines or names of executables. This may produce some false positives.

        .. note:: This requires tools to exist in OpenCTI. The :octigh:`MITRE
                  connector <connectors/tree/master/external-import/mitre>`
                  provides a number of tools, along with a number of other
                  very useful entities.
        """
        URL = "url"
        """
        Enrich :stix:`URLs <#_ah3hict2dez0>`

        The following properties are set:

        - value
        """
        UserAgent = "user-agent"
        """
        Enrich user agents strings

        This is a custom :term:`SCO` provided by OpenCTI. Very few fields contain user agent strings. The only one so far are provided by the :term:`AWS` and Office 365 integrations.

        The following properties are set:

        - value
        """
        Vulnerability = "vulnerability"
        """
        Enrich :stix:`vulnerabilities <#_q5ytzmajn6re>`

        Vulnerabilities are enriched from Wazuh's vulnerability checker, from
        both events created when the vulnerabilities are detected, and when
        they are resolved.

        The following properties may be set (most are typically available):

        - name (always)
        - CVSS - Score (x_opencti_cvss_base_score)
        - CVSS3 - Severity (x_opencti_cvss_base_severity)
        - CVSS3 - Attack vector (x_opencti_cvss_attack_vector)
        - CVSS3 - Integrity impact (x_opencti_cvss_integrity_impact)
        - CVSS3 - Availability impact (x_opencti_cvss_availability_impact)
        - CVSS3 - Confidentiality impact (x_opencti_cvss_confidentiality_impact)

        Although alerts contain more metadata, there is no place to put them in
        the vulnerability :term:`SDO`, and the connector will not override the
        description, since it typically contains useful information imported
        from another source, like MITRE.
        """

    types: set[EntityType] = Field(title="Enrichment types", default=set(EntityType))
    """
    Which entity types to enrich

    The set may be specified as a comma-separated string, like

    - "software,process"
    - "Tool, URL, user-agent"
    - "all"

    The special string "all" includes all supported entity types.
    """

    filename_behaviour: set[FilenameBehaviour] = {
        FilenameBehaviour.CreateDir,
        FilenameBehaviour.RemovePath,
    }
    """
    How Filename STIX cyber observables should be created

    See attr:`FilenameBehaviour`.
    """

    enrich_urls_without_host: bool = False
    """
    Enrich URLs without scheme and host

    If true, URL observables like '/foo' and '/foo/bar?baz=qux' will be
    created. If false, URLs must include scheme (like 'http://') and host
    ('mylocalhost', 'example.org') etc.
    """

    @field_validator("types", mode="before")
    @classmethod
    def parse_types_string(cls, types):
        """
        Convert a comma-separated string of types to a set

        Examples:

        >>> sorted(EnrichmentConfig.parse_types_string('process,file'))
        ['file', 'process']
        >>> EnrichmentConfig.parse_types_string('all') == set(EnrichmentConfig.EntityType)
        True
        """
        return comma_string_to_set(types, cls.EntityType)

    @field_validator("filename_behaviour", mode="before")
    @classmethod
    def parse_behaviour_string(cls, behaviour):
        """
        Convert a comma-separated string of types to a set

        Examples:

        >>> sorted(EnrichmentConfig.parse_behaviour_string('create-dir,remove-path'))
        ['create-dir', 'remove-path']
        """
        return comma_string_to_set(behaviour, FilenameBehaviour)
