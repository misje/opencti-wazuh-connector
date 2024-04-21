import re
import ipaddress
import logging
from pydantic import BaseModel, ConfigDict
from typing import Sequence
from pycti import OpenCTIConnectorHelper
from .opensearch import OpenSearchClient
from .opensearch_dsl import Bool, Match, MultiMatch, QueryType, Regexp, Wildcard
from .utils import (
    has,
    has_any,
    oneof_nonempty,
    list_or_empty,
    escape_lucene_regex,
    escape_path,
)
from hashlib import sha256
from ntpath import basename

log = logging.getLogger(__name__)


class AlertSearcher(BaseModel):
    model_config = ConfigDict(
        arbitrary_types_allowed=True
    )  # For OpenCTIConnectorHelper
    helper: OpenCTIConnectorHelper  # for logging only
    opensearch: OpenSearchClient
    ignore_private_addrs: bool
    search_agent_ip: bool
    search_agent_name: bool

    def search(self, entity: dict, stix_entity: dict) -> dict | None:
        match entity["entity_type"]:
            case "StixFile" | "Artifact":
                return self.query_file(entity=entity, stix_entity=stix_entity)
            case "IPv4-Addr" | "IPv6-Addr":
                return self.query_addr(entity=entity)
            case "Mac-Addr":
                return self.query_mac(
                    entity=entity,
                )
            case "Network-Traffic":
                return self.query_traffic(stix_entity=stix_entity)
            case "Email-Addr":
                return self.query_email(stix_entity=stix_entity)
            case "Domain-Name" | "Hostname":
                return self.query_domain(
                    entity=entity,
                )
            case "Url":
                return self.query_url(
                    entity=entity,
                )
            case "Directory":
                return self.query_directory(stix_entity=stix_entity)
            case "Windows-Registry-Key":
                return self.query_reg_key(stix_entity=stix_entity)
            case "Windows-Registry-Value-Type":
                return self.query_reg_value(stix_entity=stix_entity)
            case "Process":
                return self.query_process(stix_entity=stix_entity)
            case "Vulnerability":
                return self.query_vulnerability(stix_entity=stix_entity)
            case "User-Account":
                return self.query_account(stix_entity=stix_entity)
            case "User-Agent":
                return self.query_user_agent(stix_entity=stix_entity)
            case _:
                raise ValueError(
                    f'{entity["entity_type"]} is not a supported entity type'
                )

    # TODO: setting: refuse to search unless path is set (parent dir or in filename)
    # TODO: when parent_directory_ref is available, use that as search path. Optionally search for filenames with paths too.
    def query_file(self, *, entity: dict, stix_entity: dict) -> dict | None:
        # TODO: wazuh_api: syscheck/id/{file,sha256}
        # TODO: Use name as well as hash if defined (optional, config)
        # TODO: if the hash is found in a reg.key value, that is also returned as a match. Okay? An enriched reg.key will be creaeted anyway.
        if (
            entity["entity_type"] == "StixFile"
            and "name" in stix_entity
            and not has_any(stix_entity, ["hashes"], ["SHA-256", "SHA-1", "MD5"])
        ):
            # size? use size too if so.
            # ideally drop regex if path is an absolute path. A bit
            # complicated if x_opencti_additional_names
            filenames = list(
                map(
                    # Escape any regex characters and normalise path
                    # escape characters:
                    lambda a: escape_lucene_regex(escape_path(a)),
                    [stix_entity["name"]]
                    + list_or_empty(stix_entity, "x_opencti_additional_names"),
                )
            )
            return self.opensearch.search_multi_regex(
                fields=[
                    "data.ChildPath",  # panda paps
                    "data.ParentPath",  # panda paps
                    "data.Path",  # panda paps
                    "data.TargetPath",  # panda paps
                    "data.audit.execve.a1",
                    "data.audit.execve.a2",
                    "data.audit.execve.a3",
                    "data.audit.execve.a4",
                    "data.audit.execve.a5",
                    "data.audit.execve.a6",
                    "data.audit.execve.a7",
                    "data.audit.file.name",
                    "data.file",
                    "data.office365.SourceFileName",
                    "data.osquery.columns.path",
                    "data.sca.check.file",
                    "data.smbd.filename",
                    "data.smbd.new_filename",
                    "data.virustotal.source.file",
                    "data.win.eventdata.file",
                    "data.win.eventdata.filePath",
                    "data.win.eventdata.image",
                    "data.win.eventdata.parentImage",
                    "data.win.eventdata.targetFilename",
                    "syscheck.path",
                ],
                # Search for paths ignoring case for better experience
                # on Windows:
                case_insensitive=True,
                regexp="|".join(
                    [
                        # Unless the filename starts with a separator
                        # or drive letter (simple approximation, but it
                        # should cover most paths in alerts), assuming
                        # this is full path, prepend a regex that
                        # ignores everything up to and including a path
                        # separator before the filename:
                        f if re.match(r"^(?:[/\\]|[A-Za-z]:)", f) else f".*[/\\\\]*{f}"
                        for filename in filenames
                        # Support any number of backslash escapes in
                        # paths (many variants are seen in the wild):
                        for f in (filename.replace(r"\\", r"\\{2,}"),)
                    ]
                ),
            )
        elif has(stix_entity, ["hashes", "SHA-256"]):
            return self.opensearch.search_multi(
                fields=["*sha256*"], value=stix_entity["hashes"]["SHA-256"]
            )
        elif has(stix_entity, ["hashes", "SHA-1"]):
            return self.opensearch.search_multi(
                fields=["*sha1*"], value=stix_entity["hashes"]["SHA-1"]
            )
        else:
            return None

    # TODO: wazuh_api: syscollector/id/netaddr?proto={ipv4,ipv6}
    def query_addr(self, *, entity: dict) -> dict | None:
        fields = [
            "*.ActorIpAddress",
            "*.ClientIP",
            "*.IP",
            "*.IPAddress",
            "*.LocalIp",
            "*.callerIp",
            "*.dest_ip",
            "*.destination_address",
            "*.dstip",
            "*.ip",
            "*.ipAddress",
            "*.ipv*.address",
            "*.local_address",
            "*.nat_destination_ip",
            "*.nat_source_ip",
            "*.remote_address",
            "*.remote_ip",
            "*.remote_ip_address",
            "*.sourceIPAddress",
            "*.source_address",
            "*.source_ip_address",
            "*.src_ip",
            "*.srcip",
            "data.win.eventdata.queryName",
            "data.osquery.columns.address",
        ]
        address = entity["observable_value"]
        # This throws if the value is not an IP address. Accept this:
        if self.ignore_private_addrs and ipaddress.ip_address(address).is_private:
            log.info(f"Ignoring private IP address {address}")
            return None

        if self.search_agent_ip:
            return self.opensearch.search_multi(
                fields=fields,
                value=address,
            )
        else:
            return self.opensearch.search(
                must=[MultiMatch(query=address, fields=fields)],
                must_not=[Match(query=address, field="agent.ip")],
            )

    # TODO: wazuh_api: syscollector/id/netiface
    def query_mac(self, *, entity: dict) -> dict | None:
        fields = [
            "*.dmac",
            "*.dst_mac",
            "*.dstmac",
            "*.mac",
            "*.smac",
            "*.src_mac",
            "*.srcmac",
            "data.osquery.columns.interface",
        ]
        return self.opensearch.search(
            should=[
                MultiMatch(query=value, fields=fields)
                for value in [
                    entity["observable_value"].lower(),
                    entity["observable_value"].upper(),
                ]
            ]
        )

    def query_traffic(self, *, stix_entity: dict) -> dict | None:
        query: Sequence[QueryType] = []
        if "src_ref" in stix_entity:
            src_ip = self.helper.api.stix_cyber_observable.read(
                id=stix_entity["src_ref"]
            )
            if src_ip and "value" in src_ip:
                query.append(
                    MultiMatch(
                        query=src_ip["value"],
                        fields=[
                            "*.LocalIp",
                            "*.local_address",
                            "*.nat_source_ip",
                            "*.sourceIp",
                            "*.source_address",
                            "*.src_ip",
                            "*.srcip",
                        ],
                    )
                )
        if "src_port" in stix_entity:
            query.append(
                MultiMatch(
                    query=stix_entity["src_port"],
                    fields=[
                        "*.local_port",
                        "*.nat_source_port",
                        "*.sourcePort",
                        "*.spt",
                        "*.src_port",
                        "*.srcport",
                        "data.IP",
                    ],
                )
            )
        if "dst_ref" in stix_entity:
            dest_ip = self.helper.api.stix_cyber_observable.read(
                id=stix_entity["dst_ref"]
            )
            if dest_ip and "value" in dest_ip:
                query.append(
                    MultiMatch(
                        query=dest_ip["value"],
                        fields=[
                            "*.dest_ip",
                            "*.destinationIp",
                            "*.destination_address",
                            "*.dstip",
                            "*.nat_destination_ip",
                            "*.remote_address",
                        ],
                    )
                )
        if "dst_port" in stix_entity:
            query.append(
                MultiMatch(
                    query=stix_entity["dst_port"],
                    fields=[
                        "*.dest_port",
                        "*.destinationPort",
                        "*.dpt",
                        "*.dstport",
                        "*.nat_destination_port",
                        "*.remote_port",
                    ],
                )
            )

        if query:
            return self.opensearch.search(query)
        else:
            return None

    def query_email(self, *, stix_entity: dict) -> dict | None:
        return self.opensearch.search_multi(
            fields=[
                "*Email",
                "*email",
                "data.office365.UserId",
            ],
            value=stix_entity["value"],
        )
        # Consier searching in data.gcp.protoPayload.metadata.event (.parameter.value=) (field is not indexed, though, "unknwon")

    def query_domain(
        self,
        *,
        entity: dict,
    ) -> dict | None:
        fields = [
            "*.HostName",
            "*.dns_hostname",
            "*.domain",
            "*.host",
            "*.hostname",
            "*.netbios_hostname",
            "data.dns.question.name",
            "data.win.eventdata.queryName",
            # Don't search for data.office365.ParticipantInfo.ParticipatingDomains. Too many results. and not useful?
        ]
        hostname = entity["observable_value"]
        if self.search_agent_name:
            return self.opensearch.search_multi(
                fields=fields,
                value=hostname,
            )
        else:
            return self.opensearch.search(
                must=[MultiMatch(query=hostname, fields=fields)]
                # TODO: configurable?:
                # data.audit.exe /usr/bin/ssh
                # data.audit.execve.a* = hostname
                # must_not={"match": {"predecoder.hostname": hostname}},
            )

    def query_url(
        self,
        *,
        entity: dict,
    ) -> dict | None:
        # TODO: Search for URL with and without trailing slash
        return self.opensearch.search_multi(
            fields=["*url", "*Url", "*.URL", "*.uri", "data.office365.MessageURLs"],
            value=entity["observable_value"],
        )

    # FIXME: Why no hits for C:\Program Files (x86)\ossec-agent\? Works in dev tools
    def query_directory(self, *, stix_entity: dict) -> dict | None:
        # TODO: go through current field list and organise into fields
        # that expects an escaped path and those that don't:
        path = escape_path(stix_entity["path"])
        # Support any number of backslash escapes in paths (many
        # variants are seen in the wild):
        regex_path = escape_lucene_regex(path).replace(r"\\", r"\\{2,}")
        regex_path = f"{regex_path}[/\\\\]+.*"
        # Search for the directory path also in filename/path fields
        # that may be of intereset (not necessarily all the same fields
        # as in File/StixFile:
        filename_searches = [
            Regexp(field=field, query=regex_path, case_insensitive=True)
            # Do not add globs here; it will throw:
            for field in [
                "data.ChildPath",
                "data.ParentPath",
                "data.Path",
                "data.TargetPath",
                "data.audit.file.name",
                "data.smbd.filename",
                "data.smbd.new_filename",
                "data.win.eventdata.image",
                "data.win.eventdata.sourceImage",
                "data.win.eventdata.targetImage",
                "syscheck.path",
            ]
        ]
        # TODO: data.win.eventdata.currentDirectory typically has trailing slash(?)
        # Make into regex with optional slash at the end?
        # Case insensitive would be best too
        return self.opensearch.search(
            should=[
                MultiMatch(
                    query=path,
                    fields=[
                        "*.currentDirectory",
                        "*.directory",
                        "*.path",
                        "*.pwd",
                        "data.SourceFilePath",
                        "data.TargetPath",
                        "data.audit.directory.name",
                        "data.home",
                        "data.pwd",
                    ],
                )
            ]
            + filename_searches
        )

    def query_reg_key(self, *, stix_entity: dict) -> dict | None:
        return self.opensearch.search_multi(
            fields=["data.win.eventdata.targetObject", "syscheck.path"],
            value=stix_entity["key"],
        )

    def query_reg_value(self, *, stix_entity: dict) -> dict | None:
        hash = None
        match stix_entity["data_type"]:
            case "REG_SZ" | "REG_EXPAND_SZ":
                hash = sha256(stix_entity["data"].encode("utf-8")).hexdigest()
            case "REG_BINARY":
                # The STIX standard says that binary data can be in any form, but in order to be able to use this type of observable at all, support only hex strings:
                try:
                    hash = sha256(bytes.fromhex(stix_entity["data"])).hexdigest()
                except ValueError:
                    log.warning(
                        f"Windows-Registry-Value-Type binary string could not be parsed as a hex string: {stix_entity['data']}"
                    )
            case _:
                log.info(
                    f"Windos-Registry-Value-Type of type {stix_entity['data_type']} is not supported"
                )
                return None

        return (
            self.opensearch.search_multi(fields=["syscheck.sha256_after"], value=hash)
            if hash
            else None
        )

    # FIXME: doesn't find "secedit /export /cfg $env:temp/secexport.cfg" in data.win.eventdata.parentCommandLine (powershell \"$null = secedit /export /cfg $env:temp/secexport.cfg; $(gc $env:temp/secexport.cfg | Select-String \\\"LSAAnonymousNameLookup\\\").ToString().Split(\\\"=\\\")[1].Trim()\")
    def query_process(self, *, stix_entity: dict) -> dict | None:
        # TODO: use wazuh API to list proceses too:
        # TODO: Create a guard against too simple search strings (one word?)
        # TODO: Compare results against observable value and ignore if they differ too much, like fjas → /usr/bin/tee customers/orsted/usvportal-grafana-provisioning/alerting/fjas.yaml
        if "command_line" in stix_entity:
            # Split the string into tokens wrapped in quotes or
            # separated by whitespace:
            tokens = re.findall(
                r"""("[^"]*"|'[^']*'|\S+)""", stix_entity["command_line"]
            )
            if len(tokens) < 1:
                return None

            log.debug(tokens)
            command = basename(tokens[0])
            esc_command = escape_lucene_regex(command)
            args = [
                # Remove any non-escaped quotes in the beginning and
                # end of each argument, and escape any paths:
                escape_path(
                    re.sub(
                        r"""^(?:(?<!\\)"|')|(?:(?<!\\)"|')$""",
                        "",
                        arg,
                    ),
                    count=8,
                )
                for arg in tokens[1:]
            ]
            return self.opensearch.search(
                should=[
                    Bool(
                        must=[
                            Regexp(
                                field=field,
                                query=f"(.+[\\\\/])?{esc_command}.*",
                                case_insensitive=True,
                            )
                        ]
                        + [
                            Wildcard(
                                field=field, query=f"*{arg}*", case_insensitive=True
                            )
                            for arg in args
                        ]
                    )
                    for field in [
                        "data.win.eventdata.commandLine",
                        "data.win.eventdata.details",
                        "data.win.eventdata.image",
                        "data.win.eventdata.parentCommandLine",
                        "data.win.eventdata.sourceImage",
                        "data.win.eventdata.targetImage",
                    ]
                ]
                + [
                    Bool(
                        must=[
                            Regexp(
                                field="data.command",
                                query=f"(.+/)?{esc_command}.*",
                                case_insensitive=True,
                            )
                        ]
                        + [
                            Wildcard(
                                field="data.command",
                                query=f"*{arg}*",
                                case_insensitive=True,
                            )
                            for arg in args
                        ]
                    )
                ]
                + [
                    Bool(
                        must=[Match(field="data.audit.command", query=command)],
                        should=[
                            MultiMatch(fields=["data.audit.execve.a*"], query=arg)
                            for arg in args
                        ],
                    )
                ]
            )
        else:
            return None

    def query_vulnerability(self, *, stix_entity: dict) -> dict | None:
        return self.opensearch.search_match(
            {
                "data.vulnerability.cve": stix_entity["name"],
                # TODO: Include solved too, and ensure Sighting from:to represents duration of CVE present in the system. Doesn't work with the current architecture that groups alerts by id.
                # "data.vulnerability.status": "Active",
            }
        )

    def query_account(self, *, stix_entity: dict) -> dict | None:
        # TODO: settings to determine where to search (aws, google, office, windows, linux)
        # TODO: what about DOMAIN\username?
        # TODO: display name? Otherwise remove from entity_value*(?)
        uid = oneof_nonempty("user_id", within=stix_entity)
        username = oneof_nonempty("account_login", within=stix_entity)
        # Some logs provide a username that also consists of a UID in parenthesis:
        if match := re.match(r"^(?P<name>[^\(]+)\(uid=(?P<uid>\d+)\)$", username or ""):
            uid = match.group("uid")
            username = match.group("name")

        username_fields = [
            "*.LoggedUser",
            "*.destination_user",
            "*.dstuser",
            "*.parentUser",
            "*.sourceUser",
            "*.source_user",
            "*.srcuser",
            "*.user",
            "*.userName",
            "*.username",
            "data.gcp.protoPayload.authenticationInfo.principalEmail",
            "data.gcp.resource.labels.email_id",
            "data.office365.UserId",
            "data.win.eventdata.samAccountname",
            "syscheck.uname_after",
            "syscheck.uname_before",
        ]
        # TODO: add more. Missing more from windows?
        uid_fields = [
            "data.userID",  # macOS
            "data.win.eventdata.subjectUserSid",
            "data.win.eventdata.targetSid",
            "syscheck.uid_after",
            "syscheck.uid_before",
            # For audit and pam:
            "*.auid",
            "*.euid",
            "*.fsuid",
            "*.inode_uid",
            "*.oauid",
            "*.obj_uid",
            "*.ouid",
            "*.ouid",
            "*.sauid",
            "*.suid",
            "*.uid",
            "data.aws.userIdentity.accountId",
            "data.aws.userIdentity.principalId",
        ]
        if username and uid:
            return self.opensearch.search(
                must=[
                    MultiMatch(query=username, fields=username_fields),
                    MultiMatch(query=uid, fields=uid_fields),
                ]
            )
        elif username:
            return self.opensearch.search_multi(fields=username_fields, value=username)
        elif uid:
            return self.opensearch.search_multi(fields=uid_fields, value=uid)
        else:
            return None

    def query_user_agent(self, *, stix_entity: dict) -> dict | None:
        return self.opensearch.search_multi(
            value=stix_entity["value"], fields=["data.aws.userAgent"]
        )
