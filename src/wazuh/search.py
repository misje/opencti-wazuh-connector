import re
import ipaddress
import logging
from pydantic import AnyUrl, BaseModel, ConfigDict, ValidationError
from typing import Sequence
from pycti import OpenCTIConnectorHelper

from .search_config import DirSearchOption, SearchConfig, FileSearchOption
from .opensearch import OpenSearchClient
from .opensearch_dsl import Bool, Match, MultiMatch, QueryType, Regexp, Term, Wildcard
from .utils import (
    field_as_list,
    get_path_sep,
    has,
    has_any,
    oneof_nonempty,
    list_or_empty,
    mac_permutations,
    escape_lucene_regex,
    escape_path,
    regex_transform_keys,
    remove_host_from_uri,
    search_fields,
)
from hashlib import sha256
from ntpath import basename, isabs

log = logging.getLogger(__name__)


class AlertSearcher(BaseModel):
    model_config = ConfigDict(
        arbitrary_types_allowed=True
    )  # For OpenCTIConnectorHelper
    helper: OpenCTIConnectorHelper
    opensearch: OpenSearchClient
    config: SearchConfig

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

    # TODO: wazuh_api: syscheck/id/{file,sha256}
    def query_file(self, *, entity: dict, stix_entity: dict) -> dict | None:
        """
        Search :stix:`File <#_99bl2dibcztv>`/:stix:`Artifact <#_4jegwl6ojbes>`
        :term:`SCOs <SCO>` for hashes, filename/paths and/or size

        - If the file has a hash (SHA-256, MD5 or SHA-1), the hash will looked
          up in any field with a matching name (*sha256*).
        - If the file also has a name, and if
          :attr:`~wazuh.search_config.SearchConfig.filesearch_options` contains
          :attr:`~wazuh.search_config.FileSearchOption.SearchNameAndHash`, the
          name is included in the search
        - If the file has no hash, a filename search is performed if
          :attr:`~wazuh.search_config.SearchConfig.filesearch_options` contains
          :attr:`~wazuh.search_config.FileSearchOption.SearchFilenameOnly`
        - If the file does not have hashes, but has a filename and a size, and
          :attr:`~wazuh.search_config.SearchConfig.filesearch_options` contains
          :attr:`~wazuh.search_config.FileSearchOption.SearchSize`, the search
          looks for the exact size in syscheck.{size_before,size_after} along
          with any of the filename
        - If the file has additional names (x_opencti_additional_names) and
          :attr:`~wazuh.search_config.SearchConfig.filesearch_options` contains
          :attr:`~wazuh.search_config.FileSearchOption.SearchAdditionalFilenames`,
          all filenames are included in the search

        Filenames and paths
        ~~~~~~~~~~~~~~~~~~~

        When searching for filenames, a number of settings dictate how to deal
        with paths. The filenames most likely do not contain path, but if they
        do, the setting
        :attr:`~wazuh.search_config.FileSearchOption.BasenameOnly` removes this
        path before searching for the filename. Otherwise, the path, regardless
        of whether is is absolute, is included in the search.

        If the file has a reference to a parent directory
        (*parent_directory_ref*), that directory's path is included in the search
        if :attr:`~wazuh.search_config.SearchConfig.filesearch_options`
        contains
        :attr:`~wazuh.search_config.FileSearchOption.IncludeParentDirRef`. If
        the filename already contains a path, it is removed and replaced with
        that of the parent directory.

        If :attr:`~wazuh.search_config.SearchConfig.filesearch_options`
        contains :attr:`~wazuh.search_config.FileSearchOption.RequireAbsPath`,
        the filename (including its parent directory's path) must be absolute
        in order to run the search.

        Matching
        ~~~~~~~~

        Regular expressions (:dsl:`Regexp <term/regexp>`) are used as long as
        :attr:`~wazuh.search_config.SearchConfig.filesearch_options` contains
        :attr:`~wazuh.search_config.FileSearchOption.AllowRegexp`. This allows
        for flexible searching, like

        - Searching for filenames regardless of the path in alerts
        - Search for paths with any backslash escaping patterns (\\\\,
          \\\\\\\\, \\\\\\\\\\\\\\\\ etc.). Wazuh's syscheck, for instance,
          uses no extra ecaping, whereas sysmon and most other events uses
          double escaping.
        - Ignoring case
          (:attr:`~wazuh.search_config.FileSearchOption.CaseInsensitive`)

        However, regular expressions may be expensive or even disabled in your
        OpenSearch instance, so when not using Regexp, :dsl:`Match
        <full-text/match>` is used instead. This requires an exact match of
        both the filename and the path.

        TODO: Mention IncludeRegValues if not moved to Analyse
        """

        # - path must have OS separator

        ##. If the entity is an Artifact: Search hashes (SHA-256, SHA-1, MD5)
        ##. If the entity is a File:

        #  #. If the entity has no hashes

        # Search filenames:
        # -----------------

        # .. mermaid::

        #    flowchart TD
        #        A[Search Artifact/File] --> B{Artifact?}
        #        B -- Yes --> C{Has hashes?}
        #        C -- Yes --> D[Search hashes]
        #        C -- No --> N[No queryable data]
        #        B -- "No (implies File)" --> E{SearchAdditionalFilenames?}
        #        E -- No --> F{IncludeParentDirRef?}
        #        E -- Yes --> G[Add x_opencti_additional_names to name list] --> F
        #        F -- Yes --> H[Replace path with that of parent dir] --> J
        #        F -- No --> I{BasenameOnly}
        #        I -- No --> J
        #        I -- Yes --> K[Remove path] --> J
        #        J{
        FOpt = FileSearchOption
        fopts = self.config.filesearch_options
        # Ensure that one of the three hash fields are non-zero:
        has_hash = bool(
            search_fields(
                stix_entity,
                ["hashes.SHA-256", "hashes.SHA-1", "hashes.MD5"],
                regex=".+",
            )
        )
        log.debug(f"Does file/Artifact have a hash: {has_hash}")
        # The only search options for an Artifact is looking up its hashes
        if entity["entity_type"] == "Artifact":
            if not has_hash:
                # Should be impossible:
                log.warning("Artifact does not have any hashes")
                return None
            else:
                log.debug("Searching for hashes in Artifact")
                return self.opensearch.search(
                    should=self.hash_query_list(stix_entity["hashes"])
                )

        filenames = field_as_list(stix_entity, "name") + (
            list_or_empty(stix_entity, "x_opencti_additional_names")
            if FOpt.SearchAdditionalFilenames in fopts
            else []
        )
        log.debug(f"File filenames: {filenames}")
        parent_path = (
            parent_dir["path"]
            if FOpt.IncludeParentDirRef in fopts
            and "parent_directory_ref" in stix_entity
            and (
                parent_dir := self.helper.api.stix_cyber_observable.read(
                    id=stix_entity["parent_directory_ref"]
                )
            )
            else None
        )
        log.debug(f"File parent path: {parent_path}")
        size = (
            stix_entity["size"]
            if "size" in stix_entity and FOpt.SearchSize in fopts
            else None
        )
        log.debug(f"File size: {size}")

        if not has_hash and FOpt.SearchFilenameOnly not in fopts:
            log.info("Observable has no hashes and SearchFilenameOnly is disabled")
            return None
        if not has_hash and not filenames:
            log.info("Observable has no hashes and no file names")
            return None

        paths = list(
            {
                parent_path + sep + filename if parent_path else filename
                for rawname in filenames
                for filename in (
                    (
                        basename(rawname)
                        # Remove path from filename if setting says so, or if
                        # there already is a parent_path from
                        # parent_directory_ref:
                        if FOpt.BasenameOnly in fopts or parent_path
                        else rawname
                    ),
                )
                for sep in ((get_path_sep(parent_path) if parent_path else None),)
            }
        )
        log.debug(f"File paths: {paths}")

        fields = [
            "data.ChildPath",  # panda paps
            "data.ParentPath",  # panda paps
            "data.Path",  # panda paps
            "data.TargetPath",  # panda paps
            "data.audit.exe",
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
        ]

        must: list[QueryType] = []
        should: list[QueryType] = []
        if has_hash:
            must += [Bool(should=self.hash_query_list(stix_entity["hashes"]))]
        elif size is not None:
            must += [MultiMatch(query=str(size), fields=["syscheck.size*"])]

        if FOpt.SearchNameAndHash in fopts or (
            not has_hash and FOpt.SearchFilenameOnly in fopts
        ):
            # TODO: don't use regex if all paths are absolute and linux-style:
            if FOpt.AllowRegexp not in fopts:
                log.debug("Not allowed to use regexp")
                abs_paths = [path for path in paths if isabs(path)]
                log.debug(f"Absolute paths: {abs_paths}")
                if not abs_paths:
                    if FOpt.RequireAbsPath in fopts:
                        log.info(
                            "RequireAbsPath is set, Regexp is not allowed and no paths are absolute"
                        )
                    else:
                        log.warning("Regexp is not allowed, and no paths are absolute")

                    if not has_hash:
                        return None

                should += [MultiMatch(query=path, fields=fields) for path in paths]
            elif FOpt.RequireAbsPath not in fopts or all(isabs(path) for path in paths):
                paths = list(
                    map(
                        # Escape any regex characters and normalise path
                        # escape characters:
                        lambda a: escape_lucene_regex(escape_path(a)),
                        paths,
                    )
                )
                should = [
                    Regexp(
                        field=field,
                        case_insensitive=(FOpt.CaseInsensitive in fopts),
                        query="|".join(
                            [
                                # Unless the path is considered absolute,
                                # prepend a regex that ignores everything up to
                                # and including a path separator before the
                                # filename:
                                p if isabs(path) else f".*[/\\\\]*{p}"
                                for path in paths
                                # Support any number of backslash escapes in
                                # paths (many variants are seen in the wild):
                                for p in (re.sub(r"\\{2,}", r"\\\\+", path),)
                            ]
                        ),
                    )
                    for field in fields
                ]
            elif FOpt.RequireAbsPath in fopts:
                log.warning("RequireAbsPath is set and no paths are absolute")
                return None

        return self.opensearch.search(must=must, should=should)

    # TODO: wazuh_api: syscollector/id/netaddr?proto={ipv4,ipv6}
    def query_addr(self, *, entity: dict) -> dict | None:
        """
        Search for IP addresses

        If :attr:`~wazuh.search_config.SearchConfig.lookup_agent_ip` is true,
        Wazuh agents' IP addresses will also be looked up. This is probably not
        useful.

        If :attr:`~wazuh.search_config.SearchConfig.ignore_private_addrs` is
        true, no search is performed if the IP address is private (`IPv4
        <https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml>`_,
        `IPv6
        <https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml>`_).
        """
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
        if (
            self.config.ignore_private_addrs
            and ipaddress.ip_address(address).is_private
        ):
            log.info(f"Ignoring private IP address {address}")
            return None

        if self.config.lookup_agent_ip:
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
        """
        Search for MAC addresses

        If :attr:`~wazuh.search_config.SearchConfig.lookup_mac_variants` is
        true, various MAC address formats will be looked up. Otherwise, only
        lower-case, colon-separated MAC addresses will be looked up.
        """
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
                for value in self.mac_variants(entity["observable_value"])
            ]
        )

    def query_traffic(self, *, stix_entity: dict) -> dict | None:
        """
        Search for network traffic

        The following properties in :stix:`Network-Traffic <#_rgnc3w40xy>` are
        considered:

        - src_ref (MAC/IPv4/IPv6 addresses only, not domain names)
        - src_port
        - dst_ref (MAC/IPv4/IPv6 addresses only, not domain names)
        - dst_port
        - protocol

        Support for domain names in sources, as well as support for the other
        properties are not implemented, because no decoders seem to provide
        these kinds of fields.

        If :attr:`~wazuh.search_config.SearchConfig.lookup_mac_variants` is
        true, various MAC address formats will be looked up. Otherwise, only
        lower-case, colon-separated MAC addresses will be looked up.

        Note that it is possible to add multiple addresses as
        sources/destinations in OpenCTI. However, only one is provided to the
        connector. The precedence is unknown.
        """
        query: Sequence[QueryType] = []
        if "src_ref" in stix_entity:
            source = self.helper.api.stix_cyber_observable.read(
                id=stix_entity["src_ref"]
            )
            log.info(f"Network-Traffix source: {source}")
            if source and source["entity_type"] == "Mac-Addr" and "value" in source:
                query.append(
                    Bool(
                        should=[
                            MultiMatch(
                                query=mac,
                                fields=[
                                    "*.mac",
                                    "*.smac",
                                    "*.src_mac",
                                    "*.srcmac",
                                ],
                            )
                            for mac in self.mac_variants(source["value"])
                        ]
                    )
                )
            elif (
                source
                and (
                    source["entity_type"] == "IPv4-Addr"
                    or source["entity_type"] == "IPv6-Addr"
                )
                and "value" in source
            ):
                query.append(
                    MultiMatch(
                        query=source["value"],
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
            elif source:
                log.warning(
                    f"Network-Traffic src_ref type {source['entity_type']} is not supported"
                )
                return None

        if "src_port" in stix_entity:
            query.append(
                MultiMatch(
                    query=str(stix_entity["src_port"]),
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
            dest = self.helper.api.stix_cyber_observable.read(id=stix_entity["dst_ref"])
            log.info(f"Network-Traffix dest: {dest}")
            if dest and dest["entity_type"] == "Mac-Addr" and "value" in dest:
                query.append(
                    Bool(
                        should=[
                            MultiMatch(
                                query=mac,
                                fields=[
                                    "*.dmac",
                                    "*.dst_mac",
                                    "*.dstmac",
                                    "*.mac",
                                ],
                            )
                            for mac in self.mac_variants(dest["value"])
                        ]
                    )
                )
            elif (
                dest
                and (
                    dest["entity_type"] == "IPv4-Addr"
                    or dest["entity_type"] == "IPv6-Addr"
                )
                and "value" in dest
            ):
                query.append(
                    MultiMatch(
                        query=dest["value"],
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
            elif dest:
                log.warning(
                    f"Network-Traffic src_ref type {dest['entity_type']} is not supported"
                )
                return None

        if "dst_port" in stix_entity:
            query.append(
                MultiMatch(
                    query=str(stix_entity["dst_port"]),
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

        if "protocols" in stix_entity:
            query.append(
                Bool(
                    should=[
                        MultiMatch(query=proto, fields=["*.protocol"])
                        for proto in stix_entity["protocols"]
                    ]
                )
            )

        if query:
            return self.opensearch.search(query)
        else:
            return None

    def query_email(self, *, stix_entity: dict) -> dict | None:
        """
        Search e-mail addresses
        """
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
        """
        Query domain names and hostnames

        If
        :attr:`~wazuh.search_config.SearchConfig.lookup_hostnames_in_cmd_line`
        is enabled, command line alerts will also be searched.
        """
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
        if self.config.lookup_hostnames_in_cmd_line:
            return self.opensearch.search(
                should=[MultiMatch(query=hostname, fields=fields)]
                + [
                    Wildcard(query=f"*{hostname}*", field=field)
                    for field in (
                        "data.win.eventdata.commandLine",
                        "data.win.eventdata.parentCommandLine",
                        "data.command",
                        "data.audit.execve.a1",
                        "data.audit.execve.a2",
                        "data.audit.execve.a3",
                        "data.audit.execve.a4",
                        "data.audit.execve.a5",
                        "data.audit.execve.a6",
                        "data.audit.execve.a7",
                    )
                ],
                must_not=[Match(query=hostname, field="predecoder.hostname")],
            )
        else:
            return self.opensearch.search(
                must=[MultiMatch(query=hostname, fields=fields)],
                must_not=[Match(query=hostname, field="predecoder.hostname")],
            )

    def query_url(
        self,
        *,
        entity: dict,
    ) -> dict | None:
        """
        Search URLs

        Some alerts, like logs from web server, only contains the path from
        URLs (scheme, host etc. are not present). If
        :attr:`~wazuh.search_config.SearchConfig.lookup_url_without_host` is
        enabled, these fields can still be matched. This is probably not useful
        for looking up :term:`IoCs <ioc>` unless you're looking for a malicious
        requests.

        If
        :attr:`~wazuh.search_config.SearchConfig.lookup_url_ignore_trailing_slash`
        is enabled, trailing slashes in the observable and in alert fields will
        be ignored.

        If none of these settings are enabled, more fields are possibly searched.
        """
        url = entity["observable_value"]
        fields = [
            "data.url",
            "data.uri",
            "data.URL",
            "data.office365.MessageURLs",
            "data.github.config.url",
            "data.office365.SiteUrl",
        ]
        if (
            not self.config.lookup_url_without_host
            and not self.config.lookup_url_ignore_trailing_slash
        ):
            return self.opensearch.search_multi(
                fields=["*url", "*Url", "*URL", "*.uri", "data.office365.MessageURLs"],
                value=url,
            )
        elif self.config.lookup_url_without_host:
            return self.opensearch.search(
                should=[
                    Regexp(
                        query=f"(.+://)?[^/]*/?{escape_lucene_regex(remove_host_from_uri(url.rstrip('/')))}"
                        + (
                            "/?" if self.config.lookup_url_ignore_trailing_slash else ""
                        ),
                        field=field,
                    )
                    for field in fields
                ]
            )
        elif self.config.lookup_url_ignore_trailing_slash:
            return self.opensearch.search(
                should=[
                    Regexp(
                        query=f"{url.rstrip('/')}/?",
                        field=field,
                    )
                    for field in fields
                ]
            )

    def query_directory(self, *, stix_entity: dict) -> dict | None:
        """
        Search :stix:`Directory <#_lyvpga5hlw52>` :term:`SCOs <SCO>` by paths/names

        Directory :term:`IoCs <IoC>` are most likely very uncommon, but
        extensive search support is still available. A number of :attr:`options
        <wazuh.search_config.DirSearchOption>` in
        :attr:`~wazuh.search_config.SearchConfig.dirsearch_options` dictate how
        the search is performed:

        - :attr:`~wazuh.search_config.DirSearchOption.MatchSubdirs` will match
          parent directories in paths, like "/foo/bar" in "/foo/bar/baz".
        - :attr:`~wazuh.search_config.DirSearchOption.SearchFilenames` will
          look for directories in filename fields as well. If disabled, fields
          that may contain either directories or absolute filename paths will
          still be searched.
        - :attr:`~wazuh.search_config.DirSearchOption.CaseInsensitive` ignores
          case when searching
        - :attr:`~wazuh.search_config.DirSearchOption.RequireAbsPath` requires
          the path in the observable to be absolute in order to perform a
          search
        - :attr:`~wazuh.search_config.DirSearchOption.NormaliseBackslashes`
          searches for several variations of backslash escaping if
          :attr:`~wazuh.search_config.DirSearchOption.AllowRegexp` is disabled.
          syscheck.path contains minimum exaping, whereas most other fields
          have twice the amount of backslashes. When regexp is enabled, the
          number of backslashes in the observable and fields are completely
          ignored.
        - :attr:`~wazuh.search_config.DirSearchOption.IgnoreTrailingSlash` will
          ignore trailing slashes in both the observable and fields


        :attr:`~wazuh.search_config.DirSearchOption.AllowRegexp` must be
        enabled for most of the search flexibility to work, and most of the
        other options requires this option to be set. See
        :attr:`~wazuh.search_config.DirSearchOption` for details.
        """
        DOpt = DirSearchOption
        dopts = self.config.dirsearch_options
        path = re.sub(r"(?:/|\\)+$", "", escape_path(stix_entity["path"]))
        if DOpt.RequireAbsPath in dopts and not isabs(path):
            log.info("Path is not absolute and RequireAbsPath is enabled")
            return None

        dir_fields = [
            "data.audit.directory.name",
            "data.SourceFilePath",
            "data.TargetPath",
            "data.home",
            "data.pwd",
            "syscheck.path",
        ]

        if DOpt.AllowRegexp not in dopts:
            path_variants = [path]
            if DOpt.NormaliseBackslashes in dopts:
                path_variants = [escape_path(path, count=i) for i in (2, 4)]

            return self.opensearch.search(
                must=[
                    MultiMatch(
                        query=path_variant,
                        fields=dir_fields
                        + [
                            "*.currentDirectory",
                            "*.directory",
                            "*.path",
                            "*.pwd",
                        ],
                    )
                    for path_variant in path_variants
                ]
            )

        path = re.sub(r"\\{2,}", r"\\\\+", escape_lucene_regex(path))
        case_insensitive = DOpt.CaseInsensitive in dopts
        match_subdirs = DOpt.MatchSubdirs in dopts
        ignore_slash = DOpt.IgnoreTrailingSlash in dopts

        should: list[QueryType] = []
        if DOpt.SearchFilenames in dopts:
            # Search for the directory path also in filename/path fields
            # that may be of intereset (not necessarily all the same fields
            # as in File/StixFile:
            should.extend(
                [
                    Regexp(
                        field=field,
                        query=f"{path}([/\\\\]+.*)?",
                        case_insensitive=case_insensitive,
                    )
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
                    ]
                ]
            )

        if match_subdirs:
            path = f"{path}([/\\\\]+.*)?"
        elif ignore_slash:
            path = f"{path}(/|\\\\)*"

        should.extend(
            [
                Regexp(
                    field=field,
                    query=path,
                    case_insensitive=case_insensitive,
                )
                for field in dir_fields
            ]
        )
        return self.opensearch.search(should=should)

    def query_reg_key(self, *, stix_entity: dict) -> dict | None:
        """
        Search Windows registry keys
        """
        return self.opensearch.search_multi(
            fields=["data.win.eventdata.targetObject", "syscheck.path"],
            value=stix_entity["key"],
        )

    def query_reg_value(self, *, stix_entity: dict) -> dict | None:
        """
        Search Windows registry values

        Wazuh's :term:`FIM` module only registers registry value's hashes, not
        values. And it only supports *REG_SZ*, *REG_EXPAND_SZ* and *REG_BINARY*
        (i.e. not numeric values, like *REG_DWORD*).

        This function will only search for registry values of type REG_{SZ,
        EXPAND_SZ, BINARY}, and it will only compare SHA-256 values (since that
        is what Wazuh's FIM/syscheck module provides).

        In order to perform a search, the observable must:

        - Have *data_type*:

          - REG_SZ
          - REG_EXPAND_SZ
          - REG_BINARY

        If the data type is REG_SZ/REG_EXPAND_SZ, a SHA-256 hash is taken from
        the value (*data*). If the data type is REG_BINARY, the contents is
        expected to be a *hex string*, of which a SHA-256 hash is computed.
        """
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
                    return None
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
        """
        TODO
        """
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
        """
        Search vulnerability events

        Results will typically contain an event when the vulnerability was
        first detected, then later when the vulnerability was "resolved" due to
        an package upgrade.
        """
        return self.opensearch.search_match(
            {
                "data.vulnerability.cve": stix_entity["name"],
            }
        )

    def query_account(self, *, stix_entity: dict) -> dict | None:
        """
        TODO
        """
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
            "*.user.name",
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
            "*.user.id",
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
        """
        Search user agents
        """
        return self.opensearch.search_multi(
            value=stix_entity["value"], fields=["data.aws.userAgent"]
        )

    def hash_query_list(self, hashes: dict) -> list[MultiMatch]:
        return [
            MultiMatch(query=query, fields=[field])
            for field, query in regex_transform_keys(
                hashes, {"SHA-256": "*sha256*", "SHA-1": "*sha1*", "MD5": "*md5*"}
            ).items()
        ]

    def mac_variants(self, mac: str) -> list[str]:
        return mac_permutations(mac) if self.config.lookup_mac_variants else [mac]
