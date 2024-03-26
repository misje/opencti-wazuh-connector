import stix2
import re
from pydantic import BaseModel, ConfigDict, field_validator
from ntpath import basename
from enum import Enum
from typing import Any, Callable
from pycti import (
    AttackPattern,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)
from .stix_helper import (
    StixHelper,
)
from .utils import (
    has,
    first_or_none,
    first_or_empty,
    search_fields,
    search_field,
    field_compare,
    non_none,
    regex_transform,
    ip_protos,
    connection_string,
)

# TODO: Move a lot into stix_helper


class Type(Enum):
    AttackPattern = "attack-pattern"
    Tool = "tool"
    Account = "user-account"
    URL = "url"
    File = "file"
    Directory = "directory"
    RegistryKey = "windows-registry-key"
    NetworkTraffic = "network-traffic"


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
            if types == "all":
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
        if Type.File in self.types:
            bundle += self.enrich_files(incident=incident, alerts=alerts)
        if Type.Directory in self.types:
            bundle += self.enrich_dirs(incident=incident, alerts=alerts)
        if Type.RegistryKey in self.types:
            bundle += self.enrich_reg_keys(incident=incident, alerts=alerts)
        # TOOD: enrich ip addresses and mac addrs
        if Type.NetworkTraffic in self.types:
            bundle += self.enrich_traffic(incident=incident, alerts=alerts)

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
        self.helper.log_debug(f"MITRE IDS: {mitre_ids}")
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
                    ],
                },
                "user_id": {
                    r"(?<=\(uid=)\d+(?=\)$)": ["data.srcuser", "data.dstuser"],
                    ".+": [
                        "data.audit.uid",
                        "data.userId",
                        "data.uid",
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
        # FIXME: add a re_negate to search_fields and exclude HKEY_:
        # First search for fields that may contain filenames/paths, but without hashes:
        results = {
            match: {
                "field": field,
                "sco": self.stix.create_sco("StixFile", value=match),
                "alert": alert,
            }
            for alert in alerts
            for field, match in search_fields(
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
            # A NetworkTraffic object isn't interesting if we have a least two addresses or ports:
            if non_none(src_ref, src_port, dst_ref, dst_port, threshold=2)
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

    def create_enrichment_obs_from_search(
        self,
        *,
        incident: stix2.Incident,
        alerts: list[dict],
        type: str,
        fields: list[str],
    ):
        results = {
            match: {
                "field": field,
                "sco": self.stix.create_sco(type, value=match),
                "alert": alert,
            }
            for alert in alerts
            for field, match in search_fields(alert["_source"], fields).items()
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
        self.helper.log_info(results)
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
