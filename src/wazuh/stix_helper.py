import stix2
import re
from pycti import OpenCTIConnectorHelper, Tool
from pydantic import BaseModel
from typing import Annotated, Any, Final, Literal, Sequence
from .utils import (
    first_or_none,
    oneof,
    oneof_nonempty,
    allof_nonempty,
    ip_proto,
    compare_field,
)

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
    "TLP:CLEAR", "TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER-STRICT", "TLP:RED"
]

DUMMY_INDICATOR_ID: Final[str] = "indicator--167565fe-69da-5e2f-a1c1-0542736f9f9a"


class StandardID:
    """
    A string-like type that validates against STIX [object-type]--[UUID]
    """

    def __init__(self, id: str):
        self._id = id
        if not re.match(
            r"^.+--[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            self._id,
            re.IGNORECASE,
        ):
            raise ValueError(f"{self._id} is not a valid UUID")

    def _str__(self):
        return self._id


# TODO: return StandardID|None
def tlp_marking_from_string(tlp_string: str | None):
    """
    Map a TLP string to a corresponding marking definition, or None

    Any characters ut to and including ":" are stripped and case is ignored.
    """
    if tlp_string is None:
        return None

    match re.sub(r"^[^:]+:", "", tlp_string).lower():
        case "clear" | "white":
            return stix2.TLP_WHITE.id
        case "green":
            return stix2.TLP_GREEN.id
        case "amber":
            return stix2.TLP_AMBER.id
        case "amber+strict":
            return "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"
        case "red":
            return stix2.TLP_RED
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


class StixHelper(BaseModel):
    """
    Helper class to simplify creation of STIX entities
    """

    common_properties: dict[str, Any] = {}
    sco_labels: list[str] = []

    def create_tool(self, name: str):
        return stix2.Tool(
            id=Tool.generate_id(name),
            name=name,
            allow_custom=True,
            **self.common_properties,
        )

    def create_file(self, names: list[str], sha256: str):
        return stix2.File(
            name=first_or_none(names),
            hash={"SHA-256": sha256} if sha256 else None,
            allow_custom=True,
            **self.common_properties,
            x_opencti_additional_names=names[1:],
        )

    def create_addr_sco(self, address: str, **properties):
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

    def create_sco(self, type: str, value: str, **properties):
        """
        Create a SCO from its type name and properties
        """
        common_attrs = {
            "allow_custom": True,
            **self.common_properties,
            "labels": self.sco_labels,
        }
        match type:
            case "Directory":
                return stix2.Directory(path=value, **common_attrs, **properties)
            case "Domain-Name":
                return stix2.DomainName(value=value, **common_attrs, **properties)
            case "Email-Addr":
                return stix2.EmailAddress(value=value, **common_attrs, **properties)
            case "IPv4-Addr":
                return stix2.IPv4Address(value=value, **common_attrs, **properties)
            case "IPv6-Addr":
                return stix2.IPv6Address(value=value, **common_attrs, **properties)
            case "Mac-Addr":
                return stix2.MACAddress(value=value, **common_attrs, **properties)
            case "Url":
                return stix2.URL(value=value, **common_attrs, **properties)
            case "User-Account":
                return self.create_account_from_username(value, **properties)
            case "StixFile":
                return stix2.File(name=value, **common_attrs, **properties)
            case "Windows-Registry-Key":
                return stix2.WindowsRegistryKey(key=value, **common_attrs, **properties)
            case _:
                raise ValueError(f"Enrichment SCO {type} not supported")

    def create_account_from_username(self, username: str, **stix_properties):
        """
        Create a User-Account from a string that may container a username or
        both a username and a user ID

        If the username is of the form "name(uid=digits)", the uid is extracted
        and the resulting UserAccount will have both account_login and user_id
        set, otherwise account_login will be used.
        """
        uid = None
        # Some logs provide a username that also consists of a UID in parenthesis:
        if match := re.match(r"^(?P<name>[^\(]+)\(uid=(?P<uid>\d+)\)$", username or ""):
            uid = int(match.group("uid"))
            username = match.group("name")
        #
        # TODO: what about DOMAIN\username? set account_type = windows-domain

        return stix2.UserAccount(
            account_login=username,
            user_id=uid,
            allow_custom=True,
            **self.common_properties,
            lables=self.sco_labels,
            **stix_properties,
        )

    # TODO: Revisit the usefulness of replacing files. What about all the refs
    # created?
    def aggregate_files(self, bundle: STIXList) -> STIXList:
        files: dict[Annotated[str, "SHA-256"], set[Annotated[str, "Filenames"]]] = {
            file.hashes["SHA-256"]: {
                file2.name
                for file2 in files
                if compare_field(file, file2, "hashes.SHA-256")
            }
            for files in ([obj for obj in bundle if isinstance(obj, stix2.File)],)
            for file in files
            if "hashes" in file and "SHA-256" in file.hashes
        }

        return [self.create_file(list(names), hash) for hash, names in files.items()]
