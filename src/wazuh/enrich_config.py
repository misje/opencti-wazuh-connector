from pydantic import (
    Field,
    field_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import TypeVar

from .utils import comma_string_to_set
from enum import Enum

# TODO: test if a member has a union (e.g. TLPLiteral|str), and doesn't have a
# validator that changes the type, that the resulting object has the most
# strong type. If so, add these unions and remove "type:ignore" comments from
# test code


class FilenameBehaviour(Enum):
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
    # FIXME: implement: (each parent dir as individual object)
    # IndividualParentDirs


class EnrichmentConfig(BaseSettings):
    """
    This configuration dictates how the connector should enrich incidents with
    observables and other entities
    """

    model_config = SettingsConfigDict(
        env_prefix="WAZUH_ENRICH_", validate_assignment=True
    )

    class EntityType(Enum):
        """
        Entity types to enrich

        See :doc:`enrichment` for details.
        """

        Account = "user-account"
        """
        Enrich :stix:`user accounts <#_azo70vgj1vm2>`

        User accounts are enriched from FIXME.
        """
        AttackPattern = "attack-pattern"
        """
        Enrich :stix:`attack patterns <#_axjijf603msy>` (MITRE)

        Create and reference MITRE TTPs from rule.mitre.id. Only the MITRE ID is
        used, so unless another connector like :ghconnector:`mitre
        <external-import/mitre>` is used, the attack patterns created by
        opencti-wazuh will be empty, containing only the MITRE ID.
        """
        Directory = "directory"
        """
        Enrich :stix:`directories <#_lyvpga5hlw52>` from

            * data.audit.directory.name
            * data.home
            * data.osquery.columns.directory
            * data.pwd

        The following properties are set:

            * path
        """
        Domain = "domain-name"
        """
        Enrich :stix:`domain names <#_prhhksbxbg87>` from

            * data.dns.question.name
            * data.office365.ParticipantInfo.ParticipatingDomains
            * data.osquery.columns.hostname
            * data.win.eventdata.queryName
            * data.win.system.computer

        The following properties are set:

            * value
        """
        EMailAddr = "email-addr"
        """
        Enrich :stix:`e-mail addresses <#_wmenahkvqmgj>` from

            * data.gcp.protoPayload.authenticationInfo.principalEmail
            * data.office365.UserId

        The following properties are set:

            * value
        """
        File = "file"
        """
        Enrich :stix:`files <#_99bl2dibcztv>`. File names (name and
        x_opencti_additional_names) are fetched from

            * data.ChildPath
            * data.ParentPath
            * data.Path
            * data.TargetFilename
            * data.TargetPath
            * data.audit.file.name
            * data.audit.file.name
            * data.file
            * data.sca.check.file
            * data.smbd.filename
            * data.smbd.new_filename
            * data.virustotal.source.file
            * data.win.eventdata.file
            * data.win.eventdata.filePath

        Hashes (MD5, SHA-1, and SHA-256) are fetched from

            * data.osquery.columns.md5
            * data.osquery.columns.sha1
            * data.osquery.columns.sha256
            * syscheck.md5_after
            * syscheck.sha1_after
            * syscheck.sha256_after

        If FIXME:filename_behaviour is FIXME, a nested Directory observable
        will also be created and set as *parent directory*. If FIXME is FIXME,
        the filename will contain only the filename, otherwise the full path
        will be used as filename. This also applies to all filenames in
        x_opencti_additional_names.

        FIXME: size and othes
        """
        IPv4Address = "ipv4-addr"
        IPv6Address = "ipv6-addr"
        MAC = "mac-addr"
        NetworkTraffic = "network-traffic"
        Process = "process"
        RegistryKey = "windows-registry-key"
        Tool = "tool"
        URL = "url"
        UserAgent = "user-agent"

    types: set[EntityType] | str = Field(title="Enrichment types", default=set())
    """
    Which entity types to enrich
    """

    # TODO: here and elsewhere: custom EnvSetttingsSource that transforms from string:
    filename_behaviour: set[FilenameBehaviour] | str = {
        FilenameBehaviour.CreateDir,
        FilenameBehaviour.RemovePath,
    }
    """
    How Filename STIX cyber observables should be created

    See attr:`FilenameBehaviour`.
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
