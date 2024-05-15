from __future__ import annotations
import stix2
import re
import dateparser
import logging
from pydantic import BaseModel, ConfigDict
from ntpath import basename
from typing import Annotated, Any, Callable, Literal, Mapping
from pycti import (
    AttackPattern,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    Vulnerability,
)
from .stix_helper import (
    STIXList,
    StixHelper,
    SCOBundle,
    find_hashes,
)
from .utils import (
    REGISTRY_PATH_REGEX,
    SID_REGEX,
    SafeProxy,
    create_if,
    dict_member_list_first_or_remove,
    field_or_empty,
    first_field,
    float_or_none,
    has,
    has_atleast,
    first_or_none,
    first_or_empty,
    join_values,
    none_unless_threshold,
    remove_reg_paths,
    search_fields,
    search_field,
    field_compare,
    non_none,
    ip_proto,
    ip_protos,
    connection_string,
    validate_mac,
    normalise_mac,
    simplify_field_names,
    parse_sha256,
    oneof,
    remove_empties,
)
from .enrich_config import EnrichmentConfig

log = logging.getLogger(__name__)

EType = EnrichmentConfig.EntityType

# TODO: Move a lot into stix_helper
# TODO: set last_seen in related-to relationships

# TODO: DO set/update descriptions (optionally?). As long as connector has
# suitable confidence level, it will not overwrite existing descriptions.

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


def infer_protos_from_alert(alert: dict) -> set[str]:
    protos = set()

    if "sshd" in field_or_empty(alert, "rule.groups", list):
        protos.add("ssh")
    if "smbd" in field_or_empty(alert, "rule.groups", []):
        protos.add("smb")
    if any(
        keyword in field_or_empty(alert, "rule.groups", str)
        for keyword in ("ftpd", "msftp", "proftpd", "vsftpd", "pure-ftpd")
    ):
        protos.add("ftp")
    # TODO: http/https

    return protos


class Enricher(BaseModel):
    model_config = ConfigDict(
        arbitrary_types_allowed=True
    )  # For OpenCTIConnectorHelper
    helper: OpenCTIConnectorHelper
    config: EnrichmentConfig
    stix: StixHelper
    tools: list[stix2.Tool] = []

    def enrich_incident(self, *, incident: stix2.Incident, alerts: list[dict]):
        bundle = []
        # TODO: Create ObservedData too(?)
        # TODO: All of the searched fields in these enrichment functions need a lot of QA
        if EType.AttackPattern in self.config.types:
            bundle += self.enrich_incident_mitre(incident=incident, alerts=alerts)
        if EType.Tool in self.config.types:
            bundle += self.enrich_incident_tool(incident=incident, alerts=alerts)
        if EType.Account in self.config.types:
            bundle += self.enrich_accounts(incident=incident, alerts=alerts)
        if EType.URL in self.config.types:
            bundle += self.enrich_urls(incident=incident, alerts=alerts)
        if EType.EMailAddr in self.config.types:
            bundle += self.enrich_email_addrs(incident=incident, alerts=alerts)
        if EType.File in self.config.types:
            bundle += self.enrich_files(incident=incident, alerts=alerts)
        if EType.Directory in self.config.types:
            bundle += self.enrich_dirs(incident=incident, alerts=alerts)
        if EType.RegistryKey in self.config.types:
            bundle += self.enrich_reg_keys(incident=incident, alerts=alerts)
        if EType.IPv4Address in self.config.types:
            bundle += self.enrich_addrs(
                incident=incident, alerts=alerts, proto="IPv4-Addr"
            )
        if EType.IPv6Address in self.config.types:
            bundle += self.enrich_addrs(
                incident=incident, alerts=alerts, proto="IPv6-Addr"
            )
        if EType.MAC in self.config.types:
            bundle += self.enrich_macs(incident=incident, alerts=alerts)
        if EType.UserAgent in self.config.types:
            bundle += self.enrich_user_agents(incident=incident, alerts=alerts)
        if EType.Process in self.config.types:
            bundle += self.enrich_processes(incident=incident, alerts=alerts)
        if EType.Software in self.config.types:
            bundle += self.enrich_software(incident=incident, alerts=alerts)
        if EType.NetworkTraffic in self.config.types:
            bundle += self.enrich_traffic(incident=incident, alerts=alerts)
        if EType.Domain in self.config.types:
            bundle += self.enrich_domains(incident=incident, alerts=alerts)
        # NOTE: references Software objects (if found), so be sure to position
        # after enrich_software:
        if EType.Vulnerability in self.config.types:
            bundle += self.enrich_vulnerabilities(incident=incident, alerts=alerts)

        return bundle

    def fetch_tools(self):
        if EType.Tool in self.config.types:
            log.info("Building list of tools")
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
        """
        Enrich User-Account

        See :attr:`~wazuh.enrich_config.EnrichmentConfig.EntityType.Account`
        """
        # TODO: Optionally guess (setting) user_id–account_name by looking for alerts where both are present (for the same agent)
        # TODO: extract SID using regex in utils on reg.key.paths
        linux_accounts = self.create_enrichment_obs_from_search_context(
            incident=incident,
            alerts=alerts,
            sco_type="User-Account",
            SCO=stix2.UserAccount,
            # TODO: Maps 0 to user for rule id 5715. Make custom code that only
            # extracts user_id in certain contexts (or not in som cases)?
            property_field_map={
                "account_login": {
                    r"^[^(]+": ["data.srcuser", "data.dstuser"],
                    ".+": [
                        "data.aws.userIdentitiy.userName",
                        "data.gcp.protoPayload.authenticationInfo.principalEmail",
                        "data.office365.UserId",
                        "data.win.eventdata.samAccountname",
                        "data.wineventdata.user",
                        "syscheck.uname_after",
                        "syscheck.uname_before",
                    ],
                },
                "user_id": {
                    r"(?<=\(uid=)\d+(?=\)$)": ["data.srcuser", "data.dstuser"],
                    ".+": [
                        "data.audit.uid",
                        "data.aws.userIdentitiy.accountId",
                        "data.uid",
                        "data.userId",
                    ],
                },
            },
            # Require at least one of account_login/user_id:
            properties_validator=lambda x: len(x) >= 1,
        )
        win_accounts = self.create_enrichment_obs_from_search(
            incident=incident,
            alerts=alerts,
            sco_type="User-Account",
            fields=["data.win.eventdata.targetObject", "syscheck.path"],
            validator=lambda x: bool(re.search(SID_REGEX, x)),
            transform=lambda x: [
                (
                    None,
                    # Remove key instead of leaving it None, otherwise creating
                    # the SCO will fail:
                    remove_empties(
                        {"user_id": SafeProxy(re.search(f"({SID_REGEX})", x)).group(1)}
                    ),
                )
            ],
        )

        return linux_accounts + win_accounts

    def enrich_urls(self, *, incident: stix2.Incident, alerts: list[dict]):
        return self.create_enrichment_obs_from_search(
            incident=incident,
            alerts=alerts,
            sco_type="Url",
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
            sco_type="Email-Addr",
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
            sco_type="Directory",
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
                "sco": self.stix.create_sco(
                    "StixFile",
                    value=match,
                    size=none_unless_threshold(size, 0),
                    hashes=hashes if hashes else None,
                    ctime=ctime,
                    mtime=mtime,
                    atime=atime,
                ),
                "alert": alert,
            }
            for alert in alerts
            for field, match in remove_reg_paths(
                # data.sca.check.file sometimes provides a list (so far with
                # only one file). Flatten:
                dict_member_list_first_or_remove(
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
                            "data.osquery.columns.path",
                            "data.sca.check.file",
                            "data.smbd.filename",
                            "data.smbd.new_filename",
                            "data.virustotal.source.file",
                            "data.win.eventdata.file",
                            "data.win.eventdata.filePath",
                            "syscheck.path",
                        ],
                    )
                )
            ).items()
            for size in (
                first_field(
                    alert["_source"], "syscheck.size_after", "syscheck.size_before"
                ),
            )
            # Only one hash should be populated in stix, according to the
            # standard, in order of preference: md5, sha-1, sha-256. OpenCTI
            # doesn't seem to care about this, and why not keep them all:
            for hashes in (
                find_hashes(
                    alert["_source"],
                    [
                        [
                            "data.osquery.columns.md5",
                            "data.osquery.columns.sha1",
                            "data.osquery.columns.sha256",
                            "syscheck.md5_after",
                            "syscheck.sha1_after",
                            "syscheck.sha256_after",
                        ],
                        # In syscheck modification events, both 'before' and
                        # 'after' hashes are present. In such cases, the
                        # 'after' hash is wanted. However, if only 'before' is
                        # present, be sure to include that one. Add 'before'
                        # hashes as a second list argument to indicate lesser
                        # preference:
                        [
                            "syscheck.md5_before",
                            "syscheck.sha1_before",
                            "syscheck.sha256_before",
                        ],
                    ],
                ),
            )
            for ctime in (
                # Timestamps can be in any sort of format, and dateparser is
                # great and doing the best thing. If it is handed an invalid
                # timestamp string (including stringified None), it just
                # returns None. Perfect in this case:
                dateparser.parse(
                    str(first_field(alert["_source"], "data.osquery.columns.ctime"))
                ),
            )
            for mtime in (
                dateparser.parse(
                    str(
                        first_field(
                            alert["_source"],
                            "syscheck.mtime_after",
                            "syscheck.mtime_before",
                            "data.osquery.columns.mtime",
                        )
                    )
                ),
            )
            for atime in (
                dateparser.parse(
                    str(first_field(alert["_source"], "data.osquery.columns.atime"))
                ),
            )
        }

        return [
            stix
            for match, meta in results.items()
            for alert in (meta["alert"],)
            for sco_bundle in (meta["sco"],)
            for stix in sco_bundle.objects()
            + [
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", incident.id, sco_bundle.sco.id
                    ),
                    created=alert["_source"]["@timestamp"],
                    **self.stix.common_properties,
                    relationship_type="related-to",
                    description=f"StixFile {match} found in {meta['field']} in alert (ID {alert['_id']}, rule ID {alert['_source']['rule']['id']}): {alert['_source']['rule']['description']}",
                    source_ref=incident.id,
                    target_ref=sco_bundle.sco.id,
                ),
            ]
        ]

    # TODO: normalise path (backspace escape count)
    # Do this for every path produced in module (optional setting)
    def enrich_reg_keys(self, *, incident: stix2.Incident, alerts: list[dict]):
        results = {
            "\\\\".join([path, value]) if value else path: {
                "field": field,
                "sco": self.stix.create_sco(
                    "Windows-Registry-Key",
                    value=path,
                    # NOTE: This produces the correct output, but due to
                    # https://github.com/OpenCTI-Platform/opencti/issues/2574,
                    # the values are not imported:
                    values=[
                        stix2.WindowsRegistryValueType(name=value, data_type=value_type)
                    ]
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
                    alert["_source"], field, regex=f"{REGISTRY_PATH_REGEX}\\\\+.*"
                ),
            )
            if path is not None
            for value_type in (search_field(alert["_source"], "syscheck.value_type"),)
            for value in (search_field(alert["_source"], "syscheck.value_name"),)
        }
        return [
            stix
            for match, meta in results.items()
            for alert in (meta["alert"],)
            for sco_bundle in (meta["sco"],)
            for stix in sco_bundle.objects()
            + [
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", incident.id, sco_bundle.sco.id
                    ),
                    created=alert["_source"]["@timestamp"],
                    **self.stix.common_properties,
                    relationship_type="related-to",
                    description=f"Windows-Registry-Key {match} found in {meta['field']} in alert (ID {alert['_id']}, rule ID {alert['_source']['rule']['id']}): {alert['_source']['rule']['description']}",
                    source_ref=incident.id,
                    target_ref=sco_bundle.sco.id,
                ),
            ]
        ]

    def enrich_addrs(
        self,
        *,
        incident: stix2.Incident,
        alerts: list[dict],
        proto: Literal["IPv4-Addr", "IPv6-Addr"],
    ):
        return self.create_enrichment_obs_from_search(
            incident=incident,
            alerts=alerts,
            sco_type=proto,
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
            == ("ipv4" if proto == "IPv4-Addr" else "ipv6"),
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
            sco_type="Mac-Addr",
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
            sco_type="User-Agent",
            fields=["data.aws.userAgent", "data.office365.UserAgent"],
            # Ignore empty strings:
            validator=lambda x: x,
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
                log.info("Not enriching Process because commandLine is empty")
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
                        # TODO: parse the rest of the hashes too (SHA1=,MD5=,SHA25=):
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
            scos = self.stix.create_sco(
                "User-Account",
                meta.creator.account_login,  # type: ignore
                user_id=meta.creator.user_id,
            )
            creator = scos.sco
            bundle += scos.objects()
        if meta.image:
            scos = self.stix.create_file(
                [meta.image.filename],  # type: ignore
                sha256=meta.image.sha256,
            )
            image = scos.sco
            bundle += scos.objects()
        if meta.parent:
            bundle += self.create_process(meta=meta.parent)

        scos = self.stix.create_sco(
            "Process",
            value=meta.pid,  # type: ignore
            cwd=meta.cwd,
            command_line=meta.command_line,
            creator_user_ref=oneof("id", within=creator),
            image_ref=oneof("id", within=image),
            parent_ref=oneof("id", within=parent),
        )
        bundle += scos.objects()
        process = scos.sco
        if incident and alert:
            bundle += [
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", incident.id, process.id
                    ),
                    created=alert["_source"]["@timestamp"],
                    **self.stix.common_properties,
                    relationship_type="related-to",
                    description=f"Process found in alert (ID {alert['_id']}, rule ID {alert['_source']['rule']['id']}): {alert['_source']['rule']['description']}",
                    source_ref=incident.id,
                    target_ref=process.id,
                ),
            ]

        return bundle

    def enrich_software(self, *, incident: stix2.Incident, alerts: list[dict]):
        # TODO: search more than just this field:
        return [
            stix2.Software(
                name=fields["name"],
                version=fields.get("version"),
                allow_custom=True,
                **self.stix.common_properties,
                labels=self.stix.sco_labels,
            )
            for alert in alerts
            for fields in (
                simplify_field_names(
                    search_fields(
                        alert["_source"],
                        [
                            "data.vulnerability.package.name",
                            "data.vulnerability.package.version",
                        ],
                    )
                ),
            )
            # Ensure that the required property 'name' is found:
            if "name" in fields
        ]

    def enrich_traffic(self, *, incident: stix2.Incident, alerts: list[dict]):
        # TODO: Add mac addrs. and domainnames too if relevant in any fields
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
                )
                + list(infer_protos_from_alert(alert["_source"])),
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
                    description=f"Network-Traffic found in alert (ID {alert['_id']}, rule ID {alert['_source']['rule']['id']}): {alert['_source']['rule']['description']}",
                    source_ref=incident.id,
                    target_ref=sco.id,
                ),
            )
        ]

    def enrich_domains(self, *, incident: stix2.Incident, alerts: list[dict]):
        return self.create_enrichment_obs_from_search(
            incident=incident,
            alerts=alerts,
            sco_type="Domain-Name",
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

    def enrich_vulnerabilities(
        self, *, incident: stix2.Incident, alerts: list[dict]
    ) -> STIXList:
        bundle: STIXList = []
        for alert in alerts:
            if not has(alert["_source"], ["data", "vulnerability"]):
                continue

            fields = simplify_field_names(
                search_fields(
                    alert["_source"],
                    [
                        "data.vulnerability.cve",  # name
                        "data.vulnerability.cvss.cvss3.base_score",  # x_opencti_cvss_base_score
                        "data.vulnerability.cvss.cvss3.vector.attack_vector",  # x_opencti_cvss_attack_vector
                        "data.vulnerability.cvss.cvss3.vector.integrity_impact ",  # x_opencti_cvss_integrity_impact
                        "data.vulnerability.cvss.cvss3.vector.availability",  # x_opencti_cvss_availability_impact
                        "data.vulnerability.cvss.cvss3.vector.confidentiality_impact",  # x_opencti_cvss_confidentiality_impact
                        "data.vulnerability.severity",  # x_opencti_cvss_base_severity (probably – worth double-checking)
                        # "data.vulnerability.references",
                        "data.vulnerability.title",  # for Software 'has' rel. desc.
                        "data.vulnerability.published",  # for Software 'has' rel. start_time
                        # Don't fetch description: opencti's vulnerability
                        # connectors typically provides a better description
                    ],
                )
            )
            vuln = stix2.Vulnerability(
                id=Vulnerability.generate_id(name=fields["cve"]),
                name=fields["cve"],
                x_opencti_cvss_base_score=float_or_none(
                    fields.get("cvss.cvss3.base_score")
                ),
                x_opencti_cvss_attack_vector=fields.get(
                    "cvss.cvss3.vector.attack_vector"
                ),
                x_opencti_cvss_integrity_impact=fields.get(
                    "cvss.cvss3.vector.integrity_impact"  # FIXME:  nowork?
                ),
                x_opencti_cvss_availability_impact=fields.get(
                    "cvss.cvss3.vector.availability"
                ),
                x_opencti_cvss_confidentiality_impact=fields.get(
                    "cvss.cvss3.vector.confidentiality_impact"
                ),
                x_opencti_cvss_base_severity=SafeProxy(fields.get("severity")).upper(),
                # TODO: Not sure how to provide source_name to references
                # when an URL is all the available information. Perhaps
                # best leave it, since OpenCTI should have good references
                # (although Wazuh provides alterantive, completing
                # resources):
                # external_references=[]
                allow_custom=True,
                **self.stix.common_properties,
                labels=self.stix.sco_labels,
            )
            bundle += [vuln]

            # enrich_software() will create softeare SCOs (if enabled). Create
            # a ref to a software object to be used in a "has"
            # relationship, and only include it if that softeware object has
            # previously been created (honour
            # EnrichmentConfig.EntityType.Software):
            if EType.Software in self.config.types and (
                sw_ref := self.software_ref_from_vuln_alert(alert)
            ):
                bundle += (
                    stix2.Relationship(
                        id=StixCoreRelationship.generate_id("has", sw_ref, vuln.id),
                        created=alert["_source"]["@timestamp"],
                        **self.stix.common_properties,
                        relationship_type="has",
                        description=fields["title"],
                        source_ref=sw_ref,
                        target_ref=vuln.id,
                        start_time=dateparser.parse(fields["published"]),
                    ),
                )

        return bundle

    # TODO: Add a precondition callable that takes an alert and returns bool.
    def create_enrichment_obs_from_search(
        self,
        *,
        incident: stix2.Incident,
        alerts: list[dict],
        sco_type: str,
        fields: list[str],
        validator: Callable[[Any], bool] | None = None,
        transform: TransformCallback | None = None,
    ):
        # Create a dict where the key is the value found by searching the
        # alert, and the value is the STIX cyber observable:
        def create_sco(match: Any) -> dict[str, SCOBundle]:
            if sco_type == "Domain-Name":
                log.info(f"Creating domain name: {match}")
            if transform:
                # If a custom transformation function is supplied, the value is
                # probably not a simple string and need to be converted. The
                # transformation function returns a list of tuples, where the
                # the first value is the observable value and the second value
                # is a dict of additional properties to pass to the SCO
                # constructor:
                return {
                    value: self.stix.create_sco(sco_type, value, **properties)
                    for transformed in transform(match)
                    for value, properties in (transformed,)
                    # There has to be at least one property:
                    if value is not None or properties
                }
            else:
                return {match: self.stix.create_sco(sco_type, match)}

        results = {
            # Create a dict so that the SRO created later has some useful
            # metadata to refer to:
            value: {
                "field": field,
                "sco": sco_bundle,
                "alert": alert,
            }
            for alert in alerts
            for field, match in search_fields(alert["_source"], fields).items()
            # If a validator is defined, validate the match found before
            # creating a SCO. The validation could in theroy be done in the
            # transform function, but it's more user-friendly to use a simple
            # validation lambda:
            if not validator or validator(match)
            for value, sco_bundle in create_sco(match).items()
        }
        return [
            stix
            for match, meta in results.items()
            for alert in (meta["alert"],)
            for sco_bundle in (meta["sco"],)
            for stix in sco_bundle.objects()
            + [
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", incident.id, sco_bundle.sco.id
                    ),
                    created=alert["_source"]["@timestamp"],
                    **self.stix.common_properties,
                    relationship_type="related-to",
                    description=f"{sco_type} {match} found in {meta['field']} in alert (ID {alert['_id']}, rule ID {alert['_source']['rule']['id']}): {alert['_source']['rule']['description']}",
                    source_ref=incident.id,
                    target_ref=sco_bundle.sco.id,
                ),
            ]
        ]

    def create_enrichment_obs_from_search_context(
        self,
        *,
        incident: stix2.Incident,
        alerts: list[dict],
        sco_type,
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
                    description=f"{sco_type} found in alert (ID {alert['_id']}, rule ID {alert['_source']['rule']['id']}): {alert['_source']['rule']['description']}",
                    source_ref=incident.id,
                    target_ref=sco.id,
                ),
            )
        ]

    def software_ref_from_vuln_alert(self, alert: Mapping) -> str | None:
        sw_fields = simplify_field_names(
            search_fields(
                alert["_source"],
                [
                    "data.vulnerability.package.name",
                    "data.vulnerability.package.version",
                ],
            )
        )
        return (
            stix2.Software(name=sw_fields["name"], version=sw_fields.get("version")).id
            if "name" in sw_fields
            else None
        )
