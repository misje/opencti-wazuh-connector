from pydantic import field_validator
from pydantic_settings import SettingsConfigDict
from typing import Any
from .config_base import ConfigBase
from enum import Enum


class FileSearchOption(Enum):
    """
    Options determining how to search for :stix:`File
    <#_99bl2dibcztv>`/:stix:`Artifact <#_4jegwl6ojbes>` :term:`SCOs <SCO>`
    """

    # TODO: SizeAsMin
    SearchSize = "search-size"
    """
    If *size* is defined in the File SCO, search for size along with filename

    If only a hash is defined, size is ignored.
    """
    SearchNameAndHash = "search-name-and-hash"
    """
    If *name* is defined in the File SCO, match filename in addition to hashes

    If a filename (*name*, and also *x_opencti_additional_names* if
    :attr:`SearchAdditionalFilenames` is set) is defined, the filename must
    match as well has the hash (see FIXME for matching behaviour).

    If disabled, filenames will still be searched if there are no hashes and
    :attr:`SearchFilenameOnly` is enabled.
    """
    SearchFilenameOnly = "search-filename-only"
    """
    Search for filenames if no hashes are defined

    Filenames in *x_opencti_additional_names* will also be searched for if
    :attr:`SearchAdditionalFilenames` is set.
    """
    SearchAdditionalFilenames = "search-additional-filenames"
    """
    Search additional filenames along with *name*

    OpenCTI's custom SCO extenion *x_opencti_additional_names* holds a list of
    additional names for a File. This settings searches all of these names just
    as it would with *name*.
    """
    BasenameOnly = "basename-only"
    """
    If *name* contains a path, remove this before searching

    OpenCTI or STIX does not explicitly forbid the filename from including a
    (full or partial) path. If this setting is not set, any path part of *name*
    (and *x_opencti_additional_names*, if :attr:`SearchAdditionalFilenames`)
    will be part of the search.

    If :attr:`IncludeParentDirRef` is set, that path is included in the search.

    If :attr:`RequireAbsPath` is set, and no path is provided by
    *parent_directory_ref* (:attr:`IncludeParentDirRef`), the search is not
    performed.

    *Basename* does not imply that the file extension is not removed.
    """
    IncludeParentDirRef = "include-parent-dir-ref"
    """
    Include :stix:`Directory<#_lyvpga5hlw52>` path in *parent_directory_ref*
    (if any) in path when searching

    A File SCO may have a *parent directory* reference to a Directory. If this
    setting is enabled, and this reference exists, this directory's path will
    be part of the resulting search path. If this setting is set, and if the
    filename already includes a path and :attr:`BasenameOnly` is not set, the
    path in the filename is replaced with that of the parent path.
    """
    # TODO: : move to Analyser (new module). Not in use yet
    IncludeRegValues = "include-reg-values"
    """
    Include registry values that matches hashes

    Wazuh's :term:`FIM` module stores hashes of registry values and produces
    events when values are created, modified and deleted. This settings
    includes registry values along with files with matching hashes. Disable
    this setting to only return files.
    """
    AllowRegexp = "allow-regexp"
    """
    Allow :dsl:`regexp <term/regexp>` queries
 
    This allows regexp queries when searching. Regexp is used to search for
    paths that are not absolute, and also to search for any number of backslash
    escapes in the resulting filename path and fields' path.
 
    .. note:: Disable this setting if *search.allow_expensive_queries* is set to
              false in your OpenSearch installation, or if regexp queries fail.
    """
    CaseInsensitive = "case-insensitive"
    """
    Perform a case-insensitive search for filenames/paths on all platforms

    .. note:: Requires :attr:`AllowRegexp` if enabled
    """
    RequireAbsPath = "require-abs-path"
    """
    Require an absolute path, either in the filename or together with its
    parent directory

    Searching for filenames without any additional restrictions, like hashes,
    size or at least a partial path (in the file name or as part of the path
    from *parent_directory_ref*, may produce a lot of noisy results. This
    setting ignores any paths produced by *parent_directory_ref::path* and
    *name* (or *x_opencti_additional_names* if
    :attr:`SearchAdditionalFilenames` is enabled) that are not absolute.
    """
    # TODO: UseWazuhAPI


class DirSearchOption(Enum):
    """
    Options determining how to search for :stix:`Directory <#_lyvpga5hlw52>`
    :term:`SCOs <SCO>`
    """

    MatchSubdirs = "match-subdirs"
    """
    Match subdirectories where the observable is a parent

    If enabled, the observable '/foo/bar' will match the path '/foo/bar/baz'.
    However, it will not match '/foo/barbaz'.

    .. note:: Requires :attr:`AllowRegexp` if enabled
    """
    SearchFilenames = "search-filenames"
    """
    Match directories in fields that contains filenames

    If not set, only directory/path fields will be searched. This setting
    implies :attr:`IgnoreTrailingSlash` and :attr:`MatchSubdirs`, because it is
    not always possible to distinguish filenames from directories in paths.

    .. note:: Requires :attr:`AllowRegexp` if enabled
    """
    CaseInsensitive = "case-insensitive"
    """
    Perform a case-insensitive search for filenames/paths on all platforms

    .. note:: Requires :attr:`AllowRegexp` if enabled
    """
    RequireAbsPath = "require-abs-path"
    """
    Require an absolute path
    """
    AllowRegexp = "allow-regexp"
    """
    Allow :dsl:`regexp <term/regexp>` queries
 
    This allows regexp queries when searching. Regexp is used to search for
    paths that are not absolute, and also to search for any number of backslash
    escapes in paths.

    Note that this may limit the number of fields searched.
 
    .. note:: Disable this setting if *search.allow_expensive_queries* is set to
              false in your OpenSearch installation, or if regexp queries fail.
    """
    NormaliseBackslashes = "normalise-backslashes"
    """
    Normalise backslashes in observable path before searching

    Replace all sequences of '\\\\' with '\\\\\\\\' and '\\\\\\\\\\\\\\\\'
    (searchng for both variants).

    If AllowRegexp is enabled, this setting is ignored, and any number of
    backslashes are searched for.
    """
    IgnoreTrailingSlash = "ignore-trailing-slash"
    """
    Disregard trailing slashes in observables and field values

    .. note:: Requires :attr:`AllowRegexp` if enabled
    """


class ProcessSearchOption(Enum):
    CaseInsensitive = "case-insensitive"


class SearchConfig(ConfigBase):
    """
    FIXME
    """

    model_config = SettingsConfigDict(
        env_prefix="WAZUH_SEARCH_", validate_assignment=True
    )

    # TODO: rename these three options with underscore:
    filesearch_options: set[FileSearchOption] = {
        FileSearchOption.SearchSize,
        FileSearchOption.SearchAdditionalFilenames,
        FileSearchOption.IncludeParentDirRef,
        FileSearchOption.IncludeRegValues,
        FileSearchOption.SearchFilenameOnly,
        FileSearchOption.AllowRegexp,
        FileSearchOption.CaseInsensitive,
    }
    """
    File/Artifact searching options

    See :attr:`FileSearchOption` for details.

    The set may be specified as a comma-separated string, like

    - "search-size,allow-regexp, case-insensitive"
    """

    dirsearch_options: set[DirSearchOption] = {
        DirSearchOption.MatchSubdirs,
        DirSearchOption.SearchFilenames,
        DirSearchOption.AllowRegexp,
        DirSearchOption.IgnoreTrailingSlash,
        DirSearchOption.CaseInsensitive,
    }
    """
    Directory searching options

    See :attr:`DirSearchOption` for details.

    The set may be specified as a comma-separated string, like

    - "match-subdirs,require-abs-path, allow-regexp"
    """

    procsearch_options: set[ProcessSearchOption] = {ProcessSearchOption.CaseInsensitive}

    #  TODO: add include_fields/exclude_fields

    lookup_agent_ip: bool = False
    """
    Whether to include agents' addresses when searching for IPv4/IPv6 address
    observables
    """
    lookup_agent_name: bool = False
    """
    Whether to search agents' names (typically, but not necessarily, hostnames)
    when searching for domain name and hostname observables
    """
    ignore_private_addrs: bool = True
    """
    Whether to ignore IP addresses in private address spaces when searching for
    IP address observables
    """
    lookup_mac_variants: bool = True
    """
    Look up all common MAC address formats

    The following formats will be looked up if enabled:

      - 01:02:03:04:ab:cd
      - 01:02:03:04:AB:CD
      - 01020304abcd
      - 01020304ABCD
      - 0102.0304.abcd
      - 0102.0304.ABCD

    If disabled, only lower-case, colon-separated MAC addresses will be looked up. 
    """
    lookup_hostnames_in_cmd_line: bool = False
    """
    Search for domain names / hostname in command line arguments

    .. note:: This query will use :dsl:`Wildcard <term/wildcard>` queries,
              which may be expensive, or even disabled in your OpenSearch
              installation (*search.allow_expensive_queries* is set to false)
              (in which case the query will fail)
    """
    lookup_url_without_host: bool = False
    """
    Search for URLs also without host

    Some alerts only have URL path without a host. This setting allows searches
    only for this path. Beware that this can produce a lot of results.

    This is probably not useful for looking up :term:`IoCs <ioc>` unless you're
    looking for a malicious requests.

    .. note:: This will use :dsl:`Wildcard <term/wildcard>` queries,
              which may be expensive, or even disabled in your OpenSearch
              installation (*search.allow_expensive_queries* is set to false)
              (in which case the query will fail)
    """
    lookup_url_ignore_trailing_slash: bool = False
    """
    Ignore trailing slash when searching for URLs

    .. note:: This will use :dsl:`Wildcard <term/wildcard>` queries,
              which may be expensive, or even disabled in your OpenSearch
              installation (*search.allow_expensive_queries* is set to false)
              (in which case the query will fail)
    """

    @field_validator("filesearch_options", mode="after")
    @classmethod
    def check_fileopt_regexp_dep(cls, opts: Any) -> Any:
        if (
            FileSearchOption.CaseInsensitive in opts
            and FileSearchOption.AllowRegexp not in opts
        ):
            raise ValueError("CaseInsensitive requires AllowRegexp")

        return opts

    @field_validator("dirsearch_options", mode="after")
    @classmethod
    def check_diropt_regexp_dep(cls, opts: Any) -> Any:
        D = DirSearchOption
        match opts:
            case (
                D.MatchSubdirs
                | D.SearchFilenames
                | D.CaseInsensitive
                | D.IgnoreTrailingSlash
            ):
                if D.AllowRegexp not in opts:
                    raise ValueError(f"{opts} requires AllowRegexp")
            case _:
                pass

        return opts
