from __future__ import annotations
import stix2
import re
from pydantic import BaseModel, ConfigDict, field_validator
from ntpath import basename
from enum import Enum
from typing import Annotated, Any, Callable, Literal
from pycti import (
    AttackPattern,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)
from .stix_helper import (
    StixHelper,
    SCO,
)
from .utils import (
    create_if,
    has,
    has_atleast,
    first_or_none,
    first_or_empty,
    first_of,
    join_values,
    remove_reg_paths,
    search_fields,
    search_field,
    field_compare,
    non_none,
    regex_transform,
    ip_proto,
    ip_protos,
    connection_string,
    validate_mac,
    normalise_mac,
    simplify_field_names,
    parse_sha256,
    oneof,
)

# TODO: Move a lot into stix_helper

TransformCallback = Callable[
    [Annotated[Any, "Field from search"]],
    Annotated[
        list[
            tuple[
                Annotated[Any, "Value to pass to SCO constructor"],
                Annotated[
                    dict[str, Any],
                    "Any additional properties to pass to SCO constructor",
                ],
            ]
        ],
        "List of tuples, one for each SCO to be created",
    ],
]


class AccountMeta(BaseModel):
    account_login: str | None = None
    user_id: str | None = None


class FileMeta(BaseModel):
    filename: str | None = None
    sha256: str | None = None


class ProcessMeta(BaseModel):
    pid: int | None = None
    cwd: str | None = None
    command_line: str
    creator: AccountMeta | None = None
    image: FileMeta | None = None
    parent: ProcessMeta | None = None


class Type(Enum):
    AttackPattern = "attack-pattern"
    Tool = "tool"
    Account = "user-account"
    URL = "url"
    File = "file"
    Directory = "directory"
    Domain = "domain-name"
    IPv4Address = "ipv4-addr"
    IPv6Address = "ipv6-addr"
    EMailAddr = "email-addr"
    RegistryKey = "windows-registry-key"
    NetworkTraffic = "network-traffic"
    MAC = "max-addr"
    UserAgent = "user-agent"
    Process = "process"


class Enricher(BaseModel):
    model_config = ConfigDict(
        arbitrary_types_allowed=True
    )  # For OpenCTIConnectorHelper
    helper: OpenCTIConnectorHelper
    stix: StixHelper
    types: set[Type]
    tools: list[stix2.Tool] = []

    @field_validator("types", mode="before")
    @classmethod
    def parse_type_string(cls, types):
        if isinstance(types, str):
            if not types:
                return set()
            elif types == "all":
                return set(Type)
            else:
                # If this is a string, parse it as a comma-separated string with
                # enum values:
                return {type_str for type_str in types.split(",")}
        else:
            # Otherwise, let pydantic validate whatever it is:
            return types

    def enrich_incident(self, *, incident: stix2.Incident, alerts: list[dict]):
        bundle = []
        # TODO: Create ObservedData too(?)
        # TODO: All of the searched fields in these enrichment functions need a lot of QA
        if Type.AttackPattern in self.types:
            bundle += self.enrich_incident_mitre(incident=incident, alerts=alerts)
        if Type.Tool in self.types:
            bundle += self.enrich_incident_tool(incident=incident, alerts=alerts)
        if Type.Account in self.types:
            bundle += self.enrich_accounts(incident=incident, alerts=alerts)
        if Type.URL in self.types:
            bundle += self.enrich_urls(incident=incident, alerts=alerts)
        if Type.EMailAddr in self.types:
            bundle += self.enrich_email_addrs(incident=incident, alerts=alerts)
        if Type.File in self.types:
            bundle += self.enrich_files(incident=incident, alerts=alerts)
        if Type.Directory in self.types:
            bundle += self.enrich_dirs(incident=incident, alerts=alerts)
        if Type.RegistryKey in self.types:
            bundle += self.enrich_reg_keys(incident=incident, alerts=alerts)
        if Type.IPv4Address in self.types:
            bundle += self.enrich_addrs(
                incident=incident, alerts=alerts, type="IPv4-Addr"
            )
        if Type.IPv6Address in self.types:
            bundle += self.enrich_addrs(
                incident=incident, alerts=alerts, type="IPv6-Addr"
            )
        if Type.MAC in self.types:
            bundle += self.enrich_macs(incident=incident, alerts=alerts)
        if Type.UserAgent in self.types:
            bundle += self.enrich_user_agents(incident=incident, alerts=alerts)
        if Type.Process in self.types:
            bundle += self.enrich_processes(incident=incident, alerts=alerts)
        # TODO: enrich software(?)
        if Type.NetworkTraffic in self.types:
            bundle += self.enrich_traffic(incident=incident, alerts=alerts)
        if Type.Domain in self.types:
            bundle += self.enrich_domains(incident=incident, alerts=alerts)

        return bundle

    def fetch_tools(self):
        if Type.Tool in self.types:
            self.helper.connector_logger.info("Building list of tools")
            self.tools = self.helper.api.tool.list()

    def enrich_incident_mitre(self, *, incident: stix2.Incident, alerts: list[dict]):
        bundle = []
        mitre_ids = [
            id
            for alert in alerts[0:1]
            for rule in (alert["_source"]["rule"],)
            if "mitre" in rule
            for id in rule["mitre"]["id"]
        ]
        for mitre_id in mitre_ids:
            pattern = stix2.AttackPattern(
                id=AttackPattern.generate_id(mitre_id, mitre_id),
                name=mitre_id,
                allow_custom=True,
                **self.stix.common_properties,
                x_mitre_id=mitre_id,
            )
            bundle += [
                pattern,
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "uses", incident.id, pattern.id
                    ),
                    created=alerts[0]["_source"]["@timestamp"],
                    **self.stix.common_properties,
                    relationship_type="uses",
                    source_ref=incident.id,
                    target_ref=pattern.id,
                ),
            ]

        return bundle

    def enrich_incident_tool(self, *, incident: stix2.Incident, alerts: list[dict]):
        bundle = []
        for alert in alerts:
            tools = []
            if (
                has(alert, ["_source", "rule", "mitre", "id"])
                and "T1053.005" in alert["_source"]["rule"]["mitre"]["id"]
            ):
                tools = [self.stix.create_tool("schtasks")]
                bundle.append(tools[0])
            elif "psexec" in alert["_source"]["rule"]["description"].casefold():
                tools = [self.stix.create_tool("PsExec")]
                bundle.append(tools[0])
            else:
                tools = [
                    self.stix.create_tool(tool["name"])
                    # TODO: filter commmon words, like "at":
                    for tool in self.tools
                    if field_compare(
                        alert["_source"],
                        [
                            "data.win.eventdata.commandLine",
                            "data.win.eventdata.details",
                            "data.win.eventdata.parentCommandLine",
                            "data.win.eventdata.image",
                            "data.win.eventdata.sourceImage",
                            "data.win.eventdata.targetImage",
                            "data.audit.command",
                            "data.command",
                        ],
                        lambda cmd_line: isinstance(cmd_line, str)
                        and tool["name"].lower()
                        in map(
                            lambda x: basename(x).lower(),
                            re.split(r"\W+", cmd_line),
                        ),
                    )
                ]

            bundle += tools + [
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id("uses", incident.id, tool.id),
                    created=alert["_source"]["@timestamp"],
                    **self.stix.common_properties,
                    relationship_type="uses",
                    source_ref=incident.id,
                    target_ref=tool.id,
                )
                for tool in tools
            ]

        return bundle

    def enrich_accounts(self, *, incident: stix2.Incident, alerts: list[dict]):
        return self.create_enrichment_obs_from_search_context(
            incident=incident,
            alerts=alerts,
            type="User-Account",
            SCO=stix2.UserAccount,
            # TODO: Maps 0 to user for rule id 5715. Make custom code that only
            # extracts user_id in certain contexts (or not in som cases)?
            property_field_map={
                "account_login": {
                    r"^[^(]+": ["data.srcuser", "data.dstuser"],
                    ".+": [
                        "syscheck.uname_after",
                        "syscheck.uname_before",
                        "data.wineventdata.user",
                        "data.win.eventdata.samAccountname",
                        "data.office365.UserId",
                        "data.aws.userIdentitiy.userName",
                    ],
                },
                "user_id": {
                    r"(?<=\(uid=)\d+(?=\)$)": ["data.srcuser", "data.dstuser"],
                    ".+": [
                        "data.audit.uid",
                        "data.userId",
                        "data.uid",
                        "data.aws.userIdentitiy.accountId",
                    ],
                },
            },
            # Require at least one of account_login/user_id:
            properties_validator=lambda x: len(x) >= 1,
        )

    def enrich_urls(self, *, incident: stix2.Incident, alerts: list[dict]):
        return self.create_enrichment_obs_from_search(
            incident=incident,
            alerts=alerts,
            type="Url",
            fields=[
                "data.url",
                "data.osquery.columns.update_url",
                "data.office365.MeetingURL",
                "data.office365.MessageURLs",
                "data.office365.RemoteItemWebUrl",
            ],
            # MessageURLs is a list, so create a SCO for each entry:
            transform=(
                lambda x: [(i, {}) for i in x] if isinstance(x, list) else [(x, {})]
            ),
        )

    def enrich_email_addrs(self, *, incident: stix2.Incident, alerts: list[dict]):
        return self.create_enrichment_obs_from_search(
            incident=incident,
            alerts=alerts,
            type="Email-Addr",
            fields=[
                "data.gcp.protoPayload.authenticationInfo.principalEmail",
                "data.office365.UserId",
            ],
            # Do not even attempt to validate an e-mail with a regex, but do a
            # simple sanity check:
            validator=lambda x: bool(re.search(".+@.+", x)),
        )

    def enrich_dirs(self, *, incident: stix2.Incident, alerts: list[dict]):
        return self.create_enrichment_obs_from_search(
            incident=incident,
            alerts=alerts,
            type="Directory",
            fields=[
                "data.audit.directory.name",
                "data.home",
                "data.osquery.columns.directory",
                "data.pwd",
            ],
        )

    def enrich_files(self, *, incident: stix2.Incident, alerts: list[dict]):
        # First search for fields that may contain filenames/paths, but without hashes:
        results = {
            match: {
                "field": field,
                "sco": self.stix.create_sco("StixFile", value=match),
                "alert": alert,
            }
            for alert in alerts
            for field, match in remove_reg_paths(
                search_fields(
                    alert["_source"],
                    [
                        "data.ChildPath",
                        "data.ParentPath",
                        "data.Path",
                        "data.TargetFilename",
                        "data.TargetPath",
                        "data.audit.file.name",
                        "data.audit.file.name",
                        "data.file",
                        "data.sca.check.file",
                        "data.smbd.filename",
                        "data.smbd.new_filename",
                        "data.virustotal.source.file",
                        "data.win.eventdata.file",
                        "data.win.eventdata.filePath",
                    ],
                )
            ).items()
        }

        # Then search in fields that also may contain hashes:
        for alert in alerts:
            for name_field, hash_fields in {
                "data.osquery.columns.path": [
                    "data.osquery.columns.md5",
                    "data.osquery.columns.sha1",
                    "data.osquery.columns.sha256",
                ],
                "syscheck.path": [
                    "syscheck.md5_after",
                    "syscheck.sha1_after",
                    "syscheck.sha256_after",
                ],
            }.items():
                name = search_field(alert["_source"], name_field)
                hashes = regex_transform(
                    search_fields(
                        alert["_source"],
                        hash_fields,
                    ),
                    {
                        ".+md5.*": "MD5",
                        ".+sha1$.*": "SHA-1",
                        ".+sha256.*": "SHA-256",
                    },
                )
                # FIXME: use regex below instead (+ HKLM etc.):
                if name and hashes and not name.startswith("HKEY_"):
                    results[name] = {
                        "field": name_field,
                        "sco": self.stix.create_sco(
                            "StixFile",
                            value=name,
                            # Only one hash should be populated in stix, according to the
                            # standard, in order of preference: md5, sha-1, sha-256.
                            # OpenCTI doesn't seem to care about this, and why not keep
                            # them all:
                            hashes=hashes,
                        ),
                        "alert": alert,
                    }
        return [
            stix
            for match, meta in results.items()
            for alert in (meta["alert"],)
            for sco in (meta["sco"],)
            for stix in (
                sco,
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", incident.id, sco.id
                    ),
                    created=alert["_source"]["@timestamp"],
                    **self.stix.common_properties,
                    relationship_type="related-to",
                    description=f"StixFile {match} found in {meta['field']} in alert (ID {alert['_id']}, rule ID {alert['_source']['rule']['id']})",
                    source_ref=incident.id,
                    target_ref=sco.id,
                ),
            )
        ]

    def enrich_reg_keys(self, *, incident: stix2.Incident, alerts: list[dict]):
        results = {
            "/".join([path, value]) if value else path: {
                "field": field,
                "sco": self.stix.create_sco(
                    "Windows-Registry-Key",
                    value=path,
                    # NOTE: This produces the correct output, but due to
                    # https://github.com/OpenCTI-Platform/opencti/issues/2574,
                    # the values are not imported:
                    values=[stix2.WindowsRegistryValueType(name=value, data_type=type)]
                    if value is not None
                    else [],
                ),
                "alert": alert,
            }
            for alert in alerts
            for field in (
                "syscheck.path",
                "data.win.eventdata.targetObject",
            )
            for path in (
                search_field(
                    alert["_source"], field, regex="^(?:HKEY_|HK(?:LM|CU|CR|U|CC)).+"
                ),
            )
            if path is not None
            for type in (search_field(alert["_source"], "syscheck.value_type"),)
            for value in (search_field(alert["_source"], "syscheck.value_name"),)
        }
        return [
            stix
            for match, meta in results.items()
            for alert in (meta["alert"],)
            for sco in (meta["sco"],)
            for stix in (
                sco,
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", incident.id, sco.id
                    ),
                    created=alert["_source"]["@timestamp"],
                    **self.stix.common_properties,
                    relationship_type="related-to",
                    description=f"Windows-Registry-Key {match} found in {meta['field']} in alert (ID {alert['_id']}, rule ID {alert['_source']['rule']['id']})",
                    source_ref=incident.id,
                    target_ref=sco.id,
                ),
            )
        ]

    def enrich_addrs(
        self,
        *,
        incident: stix2.Incident,
        alerts: list[dict],
        type: Literal["IPv4-Addr", "IPv6-Addr"],
    ):
        return self.create_enrichment_obs_from_search(
            incident=incident,
            alerts=alerts,
            type=type,
            fields=[
                "data.aws.remote_ip",
                "data.aws.source_ip_address",
                "data.dest_ip",
                "data.dstip",
                "data.gcp.protoPayload.requestMetadata.callerIp",
                "data.office365.ClientIP",
                "data.src_ip",
                "data.srcip",
                "data.win.eventdata.destinationIp",
                "data.win.eventdata.sourceIp",
            ],
            validator=lambda x: ip_proto(x)
            == ("ipv4" if type == "IPv4-Addr" else "ipv6"),
        )

    def enrich_macs(
        self,
        *,
        incident: stix2.Incident,
        alerts: list[dict],
    ):
        return self.create_enrichment_obs_from_search(
            incident=incident,
            alerts=alerts,
            type="Mac-Addr",
            fields=[
                "data.dmac",  # fireeye
                "data.dstMac",  # sonicwall
                "data.dst_mac",
                "data.dstmac",
                "data.mastersrcmac",  # fortigate
                "data.osquery.columns.interface",
                "data.osquery.columns.mac",
                "data.smac",  # fireeye
                "data.srcMac",  # sonicwall
                "data.src_mac",  # cisco-asa, sophos
                "data.srcmac",  # fortigate
            ],
            validator=validate_mac,
            # Normalise MAC addresses to lower-case hyphen-separated format, which STIX requires:
            transform=lambda x: [(normalise_mac(x), {})],
        )

    def enrich_user_agents(
        self,
        *,
        incident: stix2.Incident,
        alerts: list[dict],
    ):
        return self.create_enrichment_obs_from_search(
            incident=incident,
            alerts=alerts,
            type="User-Agent",
            fields=[
                "data.aws.userAgent",
            ],
        )

    def enrich_processes(
        self,
        *,
        incident: stix2.Incident,
        alerts: list[dict],
    ):
        return self.enrich_processes_sysmon(
            incident=incident, alerts=alerts
        ) + self.enrich_processes_auditd(incident=incident, alerts=alerts)

    def enrich_processes_sysmon(
        self,
        *,
        incident: stix2.Incident,
        alerts: list[dict],
    ):
        bundle = []
        for alert in alerts:
            data = simplify_field_names(
                search_fields(
                    alert["_source"],
                    [
                        "data.win.eventdata.commandLine",
                        "data.win.eventdata.currentDirectory",
                        "data.win.eventdata.hashes",
                        "data.win.eventdata.image",
                        "data.win.eventdata.parentCommandLine",
                        "data.win.eventdata.parentImage",
                        "data.win.eventdata.parentProcessId",
                        "data.win.eventdata.parentUser",
                        "data.win.eventdata.processId",
                        "data.win.eventdata.user",
                    ],
                )
            )
            # OpenCTI requires command_line, even if the STIX standard does not:
            if "commandLine" not in data:
                continue

            bundle += self.create_process(
                meta=ProcessMeta(
                    pid=oneof("processId", within=data),
                    cwd=oneof("currentDirectory", within=data),
                    command_line=data["commandLine"],
                    creator=create_if(
                        AccountMeta,
                        condition=lambda: "user" in data,
                        account_login=oneof("user", within=data),
                    ),
                    image=create_if(
                        FileMeta,
                        condition=lambda: has_atleast(data, "image", "hashes"),
                        filename=oneof("image", within=data),
                        sha256=parse_sha256(oneof("hashes", within=data, default="")),
                    ),
                    parent=create_if(
                        ProcessMeta,
                        condition=lambda: "parentCommandLine" in data,
                        pid=oneof("parentProcessId", within=data),
                        command_line=data["parentCommandLine"],
                        creator=create_if(
                            AccountMeta,
                            condition=lambda: "parentUser" in data,
                            account_login=oneof("parentUser", within=data),
                        ),
                        image=create_if(
                            FileMeta,
                            condition=lambda: "parentImage" in data,
                            filename=oneof("parentImage", within=data),
                        ),
                    ),
                ),
                incident=incident,
                alert=alert,
            )
        return bundle

    def enrich_processes_auditd(self, *, incident: stix2.Incident, alerts: list[dict]):
        bundle = []
        for alert in alerts:
            data = simplify_field_names(
                search_fields(
                    alert["_source"],
                    [
                        "data.audit.file.name",  # image_ref
                        "data.audit.execve",  # command_line
                        "data.audit.auid",  # creator
                        "data.audit.pid",  # pid
                        "data.audit.ppid",  # Can't use, because OpenCTI requires command_line
                    ],
                )
            )
            # OpenCTI requires command_line, even if the STIX standard does not:
            if "execve" not in data:
                continue

            bundle += self.create_process(
                meta=ProcessMeta(
                    pid=oneof("pid", within=data),
                    command_line=join_values(data["execve"], " "),
                    creator=create_if(
                        AccountMeta,
                        condition=lambda: "auid" in data,
                        user_id=oneof("auid", within=data),
                    ),
                    image=create_if(
                        FileMeta,
                        condition=lambda: "file.name" in data,
                        filename=oneof("file.name", within=data),
                    ),
                ),
                incident=incident,
                alert=alert,
            )
        return bundle

    def create_process(
        self,
        *,
        meta: ProcessMeta,
        incident: stix2.Incident | None = None,
        alert: dict | None = None,
    ):
        bundle = []
        creator = image = parent = None
        if meta.creator:
            bundle += [
                creator := self.stix.create_sco(
                    "User-Account",
                    meta.creator.account_login,  # type: ignore
                    user_id=meta.creator.user_id,
                )
            ]
        if meta.image:
            file_bundle = self.stix.create_file(
                [meta.image.filename],  # type: ignore
                sha256=meta.image.sha256,
            )

            bundle += file_bundle
            image = first_of(file_bundle, stix2.File)
        if meta.parent:
            bundle += self.create_process(meta=meta.parent)

        bundle += [
            process := self.stix.create_sco(
                "Process",
                value=meta.pid,  # type: ignore
                cwd=meta.cwd,
                command_line=meta.command_line,
                creator_user_ref=oneof("id", within=creator),
                image_ref=oneof("id", within=image),
                parent_ref=oneof("id", within=parent),
            ),
        ]
        if incident and alert:
            bundle += [
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", incident.id, process.id
                    ),
                    created=alert["_source"]["@timestamp"],
                    **self.stix.common_properties,
                    relationship_type="related-to",
                    description=f"Process found in alert (ID {alert['_id']}, rule ID {alert['_source']['rule']['id']})",
                    source_ref=incident.id,
                    target_ref=process.id,
                ),
            ]

        return bundle

    def enrich_traffic(self, *, incident: stix2.Incident, alerts: list[dict]):
        # TODO: Add domainnames too if relevant in any fields
        from_addr_fields = [
            "data.srcip",
            "data.src_ip",
            "data.win.eventdata.sourceIp",
        ]
        to_addr_fields = [
            "data.dstip",
            "data.dest_ip",
            "data.win.eventdata.destinationIp",
            "agent.ip",
        ]
        addrs = {
            addr: sco
            for alert in alerts
            for addr in search_fields(
                alert["_source"], from_addr_fields + to_addr_fields
            ).values()
            for sco in (self.stix.create_addr_sco(addr),)
        }
        results = {
            sco.id: {"sco": sco, "alert": alert}
            for alert in alerts
            for src_ref in (
                addrs.get(
                    first_or_empty(
                        list(search_fields(alert["_source"], from_addr_fields).values())
                    )
                ),
            )
            for dst_ref in (
                addrs.get(
                    first_or_empty(
                        list(search_fields(alert["_source"], to_addr_fields).values())
                    )
                ),
            )
            for src_port in (
                first_or_none(
                    list(
                        search_fields(
                            alert["_source"],
                            [
                                "data.src_port",
                                "data.srcport",
                                "data.win.eventdata.sourcePort",
                            ],
                        ).values()
                    )
                ),
            )
            for dst_port in (
                first_or_none(
                    list(
                        search_fields(
                            alert["_source"],
                            [
                                "data.dest_port",
                                "data.dstport",
                                "data.win.eventdata.destinationPort",
                            ],
                        ).values()
                    )
                ),
            )
            for protocols in (
                ip_protos(
                    *search_fields(
                        alert["_source"], from_addr_fields + to_addr_fields
                    ).values()
                )
                + list(
                    search_fields(
                        alert["_source"], ["data.win.eventdata.protocol"]
                    ).values()
                ),
            )
            # Protocols are required:
            if protocols
            # A NetworkTraffic object isn't interesting if we have a least two addresses or ports:
            and non_none(src_ref, src_port, dst_ref, dst_port, threshold=2)
            for sco in (
                stix2.NetworkTraffic(
                    src_ref=src_ref,
                    dst_ref=dst_ref,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocols=protocols,  # TODO: add protocols like ssh, http, smb from known events
                    # TOOD: add ssh, smb, ldap  protocol etc.
                    description=connection_string(
                        src_ref=src_ref,
                        src_port=src_port,
                        dst_ref=dst_ref,
                        dst_port=dst_port,
                        protos=protocols,
                    ),
                    allow_custom=True,
                    **self.stix.common_properties,
                    labels=self.stix.sco_labels,
                ),
            )
        }
        # Only includes addresses that are referenced:
        return [
            addr
            for addr in addrs.values()
            for meta in results.values()
            for traffic in (meta["sco"],)
            if addr.id in traffic.src_ref or addr.id in traffic.dst_ref
        ] + [
            stix
            for meta in results.values()
            for alert in (meta["alert"],)
            for sco in (meta["sco"],)
            for stix in (
                sco,
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", incident.id, sco.id
                    ),
                    created=alert["_source"]["@timestamp"],
                    **self.stix.common_properties,
                    relationship_type="related-to",
                    description=f"Network-Traffic found in alert (ID {alert['_id']}, rule ID {alert['_source']['rule']['id']})",
                    source_ref=incident.id,
                    target_ref=sco.id,
                ),
            )
        ]

    def enrich_domains(self, *, incident: stix2.Incident, alerts: list[dict]):
        return self.create_enrichment_obs_from_search(
            incident=incident,
            alerts=alerts,
            type="Domain-Name",
            fields=[
                "data.osquery.columns.hostname",  # FQDN
                "data.dns.question.name",
                "data.win.eventdata.queryName",
                "data.win.system.computer",
                "data.office365.ParticipantInfo.ParticipatingDomains",
            ],
            # ParticipatingDomains is a list, so create a SCO for each entry:
            transform=(
                lambda x: [(i, {}) for i in x] if isinstance(x, list) else [(x, {})]
            ),
        )

    # TODO: Add a precondition callable that takes an alert and returns bool.
    def create_enrichment_obs_from_search(
        self,
        *,
        incident: stix2.Incident,
        alerts: list[dict],
        type: str,
        fields: list[str],
        validator: Callable[[Any], bool] | None = None,
        transform: TransformCallback | None = None,
    ):
        # Create a dict where the key is the value found by searching the
        # alert, and the value is the STIX cyber observable:
        def create_sco(match: Any) -> dict[str, SCO]:
            if transform:
                # If a custom transformation function is supplied, the value is
                # probably not a simple string and need to be converted. The
                # transformation function returns a list of tuples, where the
                # the first value is the observable value and the second value
                # is a dict of additional properties to pass to the SCO
                # constructor:
                return {
                    value: self.stix.create_sco(type, value, **properties)
                    for transformed in transform(match)
                    for value, properties in (transformed,)
                }
            else:
                return {match: self.stix.create_sco(type, match)}

        results = {
            # Create a dict so that the SRO created later has some useful
            # metadata to refer to:
            value: {
                "field": field,
                "sco": sco,
                "alert": alert,
            }
            for alert in alerts
            for field, match in search_fields(alert["_source"], fields).items()
            # If a validator is defined, validate the match found before
            # creating a SCO. The validation could in theroy be done in the
            # transform function, but it's more user-friendly to use a simple
            # validation lambda:
            if not validator or validator(match)
            for value, sco in create_sco(match).items()
        }
        return [
            stix
            for match, meta in results.items()
            for alert in (meta["alert"],)
            for sco in (meta["sco"],)
            for stix in (
                sco,
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", incident.id, sco.id
                    ),
                    created=alert["_source"]["@timestamp"],
                    **self.stix.common_properties,
                    relationship_type="related-to",
                    description=f"{type} {match} found in {meta['field']} in alert (ID {alert['_id']}, rule ID {alert['_source']['rule']['id']})",
                    source_ref=incident.id,
                    target_ref=sco.id,
                ),
            )
        ]

    def create_enrichment_obs_from_search_context(
        self,
        *,
        incident: stix2.Incident,
        alerts: list[dict],
        type,
        SCO: Any,
        property_field_map: dict[str, dict[str, list[str]]],
        properties_validator: Callable[[dict[str, Any]], bool] | None = None,
    ):
        results = {
            sco.id: {
                "sco": sco,
                "alert": alert,
            }
            for alert in alerts
            for properties in (
                {
                    property: match
                    for property, map in property_field_map.items()
                    for pattern, fields in map.items()
                    for match in search_fields(
                        alert["_source"], fields, regex=pattern
                    ).values()
                },
            )
            if not properties_validator or properties_validator(properties)
            for sco in (
                SCO(
                    **properties,
                    allow_custom=True,
                    **self.stix.common_properties,
                    labels=self.stix.sco_labels,
                ),
            )
        }
        return [
            stix
            for meta in results.values()
            for alert in (meta["alert"],)
            for sco in (meta["sco"],)
            for stix in (
                sco,
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", incident.id, sco.id
                    ),
                    created=alert["_source"]["@timestamp"],
                    **self.stix.common_properties,
                    relationship_type="related-to",
                    description=f"{type} found in alert (ID {alert['_id']}, rule ID {alert['_source']['rule']['id']})",
                    source_ref=incident.id,
                    target_ref=sco.id,
                ),
            )
        ]
