import stix2
import re
from pycti import OpenCTIConnectorHelper, Tool, CustomObservableUserAgent
from pydantic import BaseModel, ConfigDict, field_validator
from typing import Any, Final, Literal, Mapping, Sequence
from .utils import (
    filter_truthly,
    first_or_none,
    oneof,
    oneof_nonempty,
    allof_nonempty,
    ip_proto,
    merge_outof,
    listify,
    regex_transform_keys,
    search_fields,
)
from enum import Enum
from ntpath import split
from collections import OrderedDict

IPAddr = stix2.IPv4Address | stix2.IPv6Address
SCO = (
    stix2.Artifact
    | stix2.AutonomousSystem
    | stix2.Directory
    | stix2.DomainName
    | stix2.EmailAddress
    | stix2.EmailMessage
    | stix2.File
    | IPAddr
    | stix2.MACAddress
    | stix2.Mutex
    | stix2.NetworkTraffic
    | stix2.Process
    | stix2.Software
    | stix2.URL
    | stix2.UserAccount
    | stix2.WindowsRegistryKey
    | stix2.X509Certificate
)
SDO = (
    stix2.AttackPattern
    | stix2.Campaign
    | stix2.CourseOfAction
    | stix2.Grouping
    | stix2.Identity
    | stix2.Incident
    | stix2.Indicator
    | stix2.Infrastructure
    | stix2.IntrusionSet
    | stix2.Location
    | stix2.Malware
    | stix2.MalwareAnalysis
    | stix2.Note
    | stix2.ObservedData
    | stix2.Opinion
    | stix2.Report
    | stix2.ThreatActor
    | stix2.Tool
    | stix2.Vulnerability
)
SRO = stix2.Relationship | stix2.Sighting
STIXList = Sequence[SCO | SDO | SRO]
TLPLiteral = Literal[
    "TLP:CLEAR", "TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"
]

DUMMY_INDICATOR_ID: Final[str] = "indicator--167565fe-69da-5e2f-a1c1-0542736f9f9a"


def validate_stix_id(id: str, object_type: str = "") -> bool:
    """
    Test whether a string is a STIX standard ID ([object-type]--[UUID])

    Examples:

    >>> validate_stix_id('indicator--167565fe-69da-5e2f-a1c1-0542736f9f9a')
    True
    >>> validate_stix_id('marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da', 'marking-definition')
    True
    >>> validate_stix_id('marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da', 'ipv4-addr')
    False
    """
    return bool(
        re.match(
            r"^.+--[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            id,
            re.IGNORECASE,
        )
    ) and id.startswith(object_type)


class SCOBundle(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    sco: SCO
    nested_objs: list[SCO] = []

    def objects(self) -> list[SCO]:
        return [self.sco] + self.nested_objs


# TODO: return StandardID|None
def tlp_marking_from_string(tlp_string: str | None):
    """
    Map a TLP string to a corresponding marking definition, or None

    Any characters ut to and including ":" are stripped and case is ignored.

    Examples:

    >>> tlp_marking_from_string('white')
    'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9'
    >>> tlp_marking_from_string('TLP:amBEr')
    'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82'
    >>> tlp_marking_from_string('foo')
    Traceback (most recent call last):
    ...
    ValueError: foo is not a valid marking definition
    """
    if tlp_string is None:
        return None

    match re.sub(r"(?i)^tlp:", "", tlp_string).lower():
        case "clear" | "white":
            return stix2.TLP_WHITE.id
        case "green":
            return stix2.TLP_GREEN.id
        case "amber":
            return stix2.TLP_AMBER.id
        case "amber+strict":
            return "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"
        case "red":
            return stix2.TLP_RED.id
        case "":
            return None
        case _:
            raise ValueError(f"{tlp_string} is not a valid marking definition")


def tlp_allowed(entity: dict, max_tlp: TLPLiteral) -> bool:
    """
    If the entity has a TLP marking definition, ensure it is within a maximum
    allowed TLP
    """
    # Not sure what the correct logic is if the entity has several TLP markings. I asumme all have to be within max:
    return all(
        OpenCTIConnectorHelper.check_max_tlp(tlp, max_tlp)
        for mdef in entity["objectMarking"]
        for tlp in (mdef["definition"],)
        if mdef["definition_type"] == "TLP"
    )


def entity_value(entity: dict) -> str | None:
    """
    Return an observable's (or vulnerability's) value
    """
    match entity["entity_type"]:
        case "StixFile" | "Artifact":
            name = oneof_nonempty("name", "x_opencti_additional_names", within=entity)
            if isinstance(name, list) and len(name):
                return name[0]
            else:
                return str(name) if name is not None else None
        case "Directory":
            return oneof("path", within=entity)
        case "Process":
            return oneof("pid", "commandLine", within=entity)
        case "Software" | "Windows-Registry-Value-Type":
            return oneof("name", within=entity)
        case "User-Account":
            return oneof_nonempty(
                "account_login", "user_id", "display_name", within=entity
            )
        case "Vulnerability":
            return oneof("name", within=entity)
        case "Windows-Registry-Key":
            return oneof("key", within=entity)
        case _:
            return oneof("value", within=entity)


def entity_values(entity: dict) -> list[Any]:
    """
    Return an observable's (or vulnerability's) values
    """
    match entity["entity_type"]:
        case "StixFile" | "Artifact":
            return allof_nonempty("name", "x_opencti_additional_names", within=entity)
        case "Directory":
            return allof_nonempty("path", within=entity)
        case "Process":
            return allof_nonempty("pid", "commandLine", within=entity)
        case "Software" | "Windows-Registry-Value-Type":
            return allof_nonempty("name", within=entity)
        case "User-Account":
            return allof_nonempty(
                "account_login", "user_id", "display_name", within=entity
            )
        case "Vulnerability":
            return allof_nonempty("name", within=entity)
        case "Windows-Registry-Key":
            return allof_nonempty("key", within=entity)
        case _:
            return allof_nonempty("value", within=entity)


def entity_name_value(entity: dict):
    """
    Return the name and value of an entity, space separated
    """
    return " ".join(filter(None, [entity["entity_type"], entity_value(entity)]))


def incident_entity_relation_type(entity: dict):
    """
    Return the expected relationship type for the entity in the incident
    """
    match entity["entity_type"]:
        case "Vulnerability":
            return "targets"
        case _:
            return "related-to"


def add_refs_to_note(note: stix2.Note, objs: STIXList) -> stix2.Note:
    # Don't use new_version(), because that requires a new modified
    # timestamp (which must be newer than created):
    return stix2.Note(
        **{prop: getattr(note, prop) for prop in note if prop != "object_refs"},
        object_refs=list(set(note.object_refs) | {obj.id for obj in objs}),
    )


def add_incidents_to_note_refs(bundle: STIXList) -> STIXList:
    return [
        add_refs_to_note(obj, incidents) if isinstance(obj, stix2.Note) else obj
        for incidents in ([obj for obj in bundle if isinstance(obj, stix2.Incident)],)
        for obj in bundle
    ]


def remove_unref_objs(bundle: STIXList) -> STIXList:
    """
    Return a new bundle only with SCOs/SDOs that are referenced in SROs

    All observables and domain objects that are referenced by relationships or
    sightings (not as nested objects) are kept in the list, in order. All
    unreferenced objects are removed.

    Examples:

    >>> f1 = stix2.File(name='foo', allow_custom=True, test_id='file_foo')
    >>> f2 = stix2.File(name='bar', allow_custom=True, test_id='file_bar')
    >>> f3 = stix2.File(name='baz', allow_custom=True, test_id='file_baz')
    >>> r1 = stix2.Relationship(relationship_type='related-to', source_ref=f1, target_ref=f2, allow_custom=True, test_id='rel')
    >>> i1 = stix2.Indicator(pattern="[file:name = 'foo']", pattern_type='stix', valid_from='2024-04-04T15:46:03.282304Z', allow_custom=True, test_id='ind')
    >>> id1 = stix2.Identity(name='id1', allow_custom=True, test_id='id1')
    >>> id2 = stix2.Identity(name='id2', allow_custom=True, test_id='id2')
    >>> id3 = stix2.Identity(name='id3', allow_custom=True, test_id='id3')
    >>> s1 = stix2.Sighting(sighting_of_ref=i1.id, where_sighted_refs=[id1, id2], allow_custom=True, test_id='sight')
    >>> bundle = [f1, r1, f2, f3, id1, i1, id2, s1, id3]
    >>> [o.test_id for o in remove_unref_objs(bundle)]
    ['file_foo', 'rel', 'file_bar', 'id1', 'ind', 'id2', 'sight']
    """
    relationships = (obj for obj in bundle if isinstance(obj, SRO))
    ref_ids = OrderedDict.fromkeys(
        id
        for rel in relationships
        for attr in (
            "source_ref",
            "target_ref",
            "sighting_of_ref",
            "observed_data_refs",
            "where_sighted_refs",
        )
        for ids in (getattr(rel, attr, []),)
        for id in listify(ids)
    )
    return [
        obj
        for obj in bundle
        if isinstance(obj, SRO) or (isinstance(obj, SCO | SDO) and obj.id in ref_ids)
    ]


def find_hashes(
    obj: Mapping, fields: list[list[str]], overwrite: bool = False
) -> dict[str, dict[str, str]]:
    """
    Return a dict suitable for the argument 'hashes' in stix2.File from hash
    properties in an alert

    The hash keys will be transformed into the keys expected by STIX, e.g.
    'sha256_after' will be replaced with 'SHA-256'. Any field containing
    'sha256' or 'sha-256' in any case will be matched. The hashes themselves
    are not verified.

    The fields in a list of list of fields, where the outer list determines the
    order of preference. The overwrite parameter determines whether a hash
    member found in a previous field list will be replaced or not.

    Examples:

    >>> alert = {"syscheck": { "md5_before": "11ee6b89a2500aa326d45bc0f0d93821", "sha256_before": "87b3bfb07fa641adf426961c9d5e8a81c321fd03c32d9afb0f761a2c876cb6a1", "sha1_after": "950c5897c1e1b8b7686b976472d19fd815beccd7", "md5_after": "502ad4209d3eb3267d08708f0807de1c", "sha1_before": "ff916c71058daa68e2951a50bed8b3e5bfd7aff3", "sha256_after": "6f2a43b4d954d9984701a23513bb4476736dd4aed5b5ec47ad99e7943eacd7bf"}}
    >>> find_hashes(alert, [['syscheck.sha256_after', 'syscheck.md5_after', 'syscheck.sha1_after'], ['syscheck.sha256_before']])
    {'SHA-256': '6f2a43b4d954d9984701a23513bb4476736dd4aed5b5ec47ad99e7943eacd7bf', 'MD5': '502ad4209d3eb3267d08708f0807de1c', 'SHA-1': '950c5897c1e1b8b7686b976472d19fd815beccd7'}
    >>> find_hashes(alert, [['syscheck.sha256_after', 'syscheck.md5_after', 'syscheck.sha1_after'], ['syscheck.sha256_before']], overwrite=True)
    {'SHA-256': '87b3bfb07fa641adf426961c9d5e8a81c321fd03c32d9afb0f761a2c876cb6a1', 'MD5': '502ad4209d3eb3267d08708f0807de1c', 'SHA-1': '950c5897c1e1b8b7686b976472d19fd815beccd7'}
    """
    hashes = {}
    for fields_pref in fields:
        hashes.update(
            (key, value)
            for key, value in regex_transform_keys(
                search_fields(obj, fields_pref),
                {
                    "(?i).+md5.*": "MD5",
                    "(?i).+sha-?1.*": "SHA-1",
                    "(?i).+sha-?256.*": "SHA-256",
                },
            ).items()
            if overwrite or key not in hashes
        )

    return hashes


class FilenameBehaviour(Enum):
    CreateDir = "create-dir"
    RemovePath = "remove-path"


class StixHelper(BaseModel):
    """
    Helper class to simplify creation of STIX entities
    """

    common_properties: dict[str, Any] = {}
    sco_labels: list[str] = []
    filename_behaviour: set[FilenameBehaviour] = {FilenameBehaviour.CreateDir}

    @field_validator("filename_behaviour", mode="before")
    @classmethod
    def parse_behaviour_string(cls, behaviour):
        if isinstance(behaviour, str):
            if not behaviour:
                return set()
            # If this is a string, parse it as a comma-separated string with
            # enum values:
            return {string for string in behaviour.split(",")}
        else:
            # Otherwise, let pydantic validate whatever it is:
            return behaviour

    def create_tool(self, name: str):
        return stix2.Tool(
            id=Tool.generate_id(name),
            name=name,
            allow_custom=True,
            **self.common_properties,
        )

    def create_file(
        self,
        names: list[str],
        *,
        sha256: str | None = None,
        **properties,
    ) -> SCOBundle:
        """
        Create a STIX file

        If sha256 is non-empty, it will be inserted into a hash object. If
        names contain more than one string, the first name will be used as
        "name", and the rest will be used as x_opencti_additional_names.

        If filename_behaviour contains CreateDir, a Directory object is created
        and referenced in parent_directory_ref. The path is extracted from the
        one of the filenames that contains a path. If filename_behaviour
        contains RemovePath, the path component of filenames will be removed.

        Examples:

        >>> h = StixHelper(filename_behaviour='')
        >>> h.create_file(names=['filename1', 'filename2'])
        SCOBundle(sco=File(type='file', spec_version='2.1', id='file--f83c036d-56f6-5246-8585-1616d42c7669', name='filename1', defanged=False, x_opencti_additional_names=['filename2']), nested_objs=[])
        >>> h.create_file(names=['/tmp/filename1', '/filename2'])
        SCOBundle(sco=File(type='file', spec_version='2.1', id='file--09765542-1408-5026-8674-8128438fc940', name='/tmp/filename1', defanged=False, x_opencti_additional_names=['/filename2']), nested_objs=[])
        >>> h = StixHelper(filename_behaviour='create-dir')
        >>> h.create_file(names=['/tmp/filename1', '/home/foo/Downloads/filename2'])
        SCOBundle(sco=File(type='file', spec_version='2.1', id='file--ed282b5e-3ebe-5d5f-81e3-d52b629abb46', name='/tmp/filename1', parent_directory_ref='directory--b7ed5105-3a80-559d-9bd6-ec208b6d813e', defanged=False, x_opencti_additional_names=['/home/foo/Downloads/filename2']), nested_objs=[Directory(type='directory', spec_version='2.1', id='directory--b7ed5105-3a80-559d-9bd6-ec208b6d813e', path='/home/foo/Downloads', defanged=False)])
        >>> h = StixHelper(filename_behaviour='create-dir,remove-path')
        >>> h.create_file(names=['filename1', '/home/foo/Downloads/filename2'])
        SCOBundle(sco=File(type='file', spec_version='2.1', id='file--901c064f-7d08-5092-b84e-851f68c67a73', name='filename1', parent_directory_ref='directory--b7ed5105-3a80-559d-9bd6-ec208b6d813e', defanged=False, x_opencti_additional_names=['filename2']), nested_objs=[Directory(type='directory', spec_version='2.1', id='directory--b7ed5105-3a80-559d-9bd6-ec208b6d813e', path='/home/foo/Downloads', defanged=False)])
        """
        path_names = {
            (path, filename) for name in names for path, filename in (split(name),)
        }
        # Sort the names in order to be able to test the function (otherwise
        # the order in the set will produce inconsistent results in doctest):
        paths = list(
            filter(lambda x: x, sorted({path_name[0] for path_name in path_names}))
        )
        filenames = list(
            filter(lambda x: x, sorted({path_name[1] for path_name in path_names}))
        )
        main_name = first_or_none(
            filenames
            if FilenameBehaviour.RemovePath in self.filename_behaviour
            else names
        )
        extra_names = (
            filenames[1:]
            if FilenameBehaviour.RemovePath in self.filename_behaviour
            else names[1:]
        )
        dir = None
        if paths and FilenameBehaviour.CreateDir in self.filename_behaviour:
            dir = stix2.Directory(
                path=paths[0],
                allow_custom=True,
                **self.common_properties,
                labels=self.sco_labels,
            )

        return SCOBundle(
            sco=stix2.File(
                # Let "properties" override properties set here (like hashes):
                **merge_outof(
                    properties,
                    name=main_name,
                    hashes={"SHA-256": sha256} if sha256 else None,
                    parent_directory_ref=dir,
                    allow_custom=True,
                    **self.common_properties,
                    labels=self.sco_labels,
                    x_opencti_additional_names=extra_names,
                )
            ),
            nested_objs=filter_truthly(dir),
        )

    def create_addr_sco(
        self, address: str, **properties
    ) -> stix2.IPv4Address | stix2.IPv6Address:
        """
        Create either an IPv4Address or IPv6Address, depending on the address
        type
        """
        match ip_proto(address):
            case "ipv4":
                SCO = stix2.IPv4Address
            case "ipv6":
                SCO = stix2.IPv6Address
            case _:
                raise ValueError(f"{address} is not a valid IP address")

        return SCO(
            value=address,
            allow_custom=True,
            **self.common_properties,
            labels=self.sco_labels,
            **properties,
        )

    def create_sco(self, type: str, value: str | None, **properties) -> SCOBundle:
        """
        Create a SCO from its type name and properties

        If value is None, properties must contain the observable value.
        """
        common_attrs = {
            "allow_custom": True,
            **self.common_properties,
            "labels": self.sco_labels,
        }

        def _create_sco(SCO, **kwargs):
            # Allow "properties" to override:
            return SCOBundle(
                sco=SCO(**merge_outof(properties, **common_attrs, **kwargs))
            )

        match type:
            case "Directory":
                return _create_sco(stix2.Directory, path=value)
            case "Domain-Name":
                return _create_sco(stix2.DomainName, value=value)
            case "Email-Addr":
                return _create_sco(stix2.EmailAddress, value=value)
            case "IPv4-Addr":
                return _create_sco(stix2.IPv4Address, value=value)
            case "IPv6-Addr":
                return _create_sco(stix2.IPv6Address, value=value)
            case "Mac-Addr":
                return _create_sco(stix2.MACAddress, value=value)
            case "Process":
                return _create_sco(stix2.Process, pid=value)
            case "Url":
                return _create_sco(stix2.URL, value=value)
            case "User-Account":
                return SCOBundle(
                    sco=self.create_account_from_username(value, **properties)
                )
            case "StixFile":
                return self.create_file(names=listify(value), **properties)
            case "User-Agent":
                return _create_sco(CustomObservableUserAgent, value=value)
            case "Windows-Registry-Key":
                return _create_sco(stix2.WindowsRegistryKey, key=value)
            case _:
                raise ValueError(f"Enrichment SCO {type} not supported")

    def create_account_from_username(self, username: str | None, **stix_properties):
        """
        Create a User-Account from a string that may container a username or
        both a username and a user ID

        If the username is of the form "name(uid=digits)", the uid is extracted
        and the resulting UserAccount will have both account_login and user_id
        set, otherwise account_login will be used.

        Examples:

        >>> h = StixHelper()
        >>> h.create_account_from_username('foo', custom_prop='bar')
        UserAccount(type='user-account', spec_version='2.1', id='user-account--234499e1-7802-5681-87df-a7667d8e3b6e', account_login='foo', defanged=False, custom_prop='bar')
        >>> h.create_account_from_username('foo(uid=1000)')
        UserAccount(type='user-account', spec_version='2.1', id='user-account--7d128e22-4162-5b1e-8df6-d6b8644c6949', user_id='1000', account_login='foo', defanged=False)
        >>> h.create_account_from_username(username=None,user_id='1000')
        UserAccount(type='user-account', spec_version='2.1', id='user-account--4b8a1e8e-e7c7-5c91-b832-b1bdad612c36', user_id='1000', defanged=False)
        """
        uid = None
        # Some logs provide a username that also consists of a UID in parenthesis:
        if username and (
            match := re.match(r"^(?P<name>[^\(]+)\(uid=(?P<uid>\d+)\)$", username or "")
        ):
            uid = int(match.group("uid"))
            username = match.group("name")
        #
        # TODO: what about DOMAIN\username? set account_type = windows-domain

        return stix2.UserAccount(
            # Let stix_properties override properties set here (like user_id):
            **merge_outof(
                stix_properties,
                account_login=username,
                user_id=oneof("user_id", within=stix_properties, default=uid),
                allow_custom=True,
                **self.common_properties,
                labels=self.sco_labels,
            )
        )

    ## TODO: Revisit the usefulness of replacing files. What about all the refs
    ## created?
    # def aggregate_files(self, bundle: STIXList) -> STIXList:
    #    files: dict[Annotated[str, "SHA-256"], set[Annotated[str, "Filenames"]]] = {
    #        file.hashes["SHA-256"]: {
    #            file2.name
    #            for file2 in files
    #            if compare_field(file, file2, "hashes.SHA-256")
    #        }
    #        for files in ([obj for obj in bundle if isinstance(obj, stix2.File)],)
    #        for file in files
    #        if "hashes" in file and "SHA-256" in file.hashes
    #    }

    #    return [self.create_file(list(names), hash) for hash, names in files.items()]
