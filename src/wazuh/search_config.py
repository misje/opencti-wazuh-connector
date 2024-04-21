from pydantic import (
    Field,
    field_validator,
)
from pydantic_settings import SettingsConfigDict
from typing import TypeVar
from .utils import comma_string_to_set
from .config_base import ConfigBase
from enum import Enum


class HashType(Enum):
    SHA256 = ("SHA-256",)
    SHA1 = ("SHA-1",)
    MD5 = "MD5"


class CommonSearchOptions(Enum):
    AllowWildcard = "allow-wildcard"
    """
    Allow :dsl:`wildcard <term/wildcard>` queries

    This allows wildcard queries when searching. If disabled, a lot of queries
    will be disabled or very limited, even if effort has been made to make
    wildcard-free, targeted alternatives.

    .. note:: Disable this setting if *search.allow_expensive_queries* is set to
              false in your OpenSearch installation, or if wildcard queries fail.

    See also :attr:`allow-regexp`.
    """
    AllowRegexp = "allow-regexp"
    """
    Allow :dsl:`regexp <term/regexp>` queries

    This allows regexp queries when searching. If disabled, a lot of queries
    will be disabled or very limited, even if effort has been made to make
    regexp-free, targeted alternatives.

    .. note:: Disable this setting if *search.allow_expensive_queries* is set to
              false in your OpenSearch installation, or if regexp queries fail.

    See also :attr:`AllowWildcard`.
    """


class FileSearchOption(Enum):
    SearchSize = "search-size"
    """
    If *size* is defined in the File SCO, search for size along with filename

    If only a hash is defined, size is ignored.
    """
    SearchFilename = "search-filename"
    """
    If *name* is defined in the File SCO, match filename in addition to hashes

    If a file name (*name*, and also *x_opencti_additional_names* if
    :attr:`SearchAdditionalFilenames` is set) is defined, the filename must
    match as well has the hash (see FIXME for matching behaviour).
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
    SearchSyscheckBefore = "search-syscheck-before"
    """
    Search Wazuh's syscheck events for files' previous/old attributes

    Wazuh's :term:`FIM` creates events when files are created, modified and
    deleted. When files are modified, alerts contain information about a file's
    old and new hash and size. This setting determines whether the old metadata
    should also be searched.

    This may be useful if alerts for when the file was created are missing,
    otherwise it will just add additional data/noise.
    """
    SearchPaths = "search-paths"
    """
    Search for filenames in fields that may not be used exclusively 
    """
    BasenameOnly = "basename-only"
    """
    If *name* contains a path, remove this before searching

    OpenCTI or STIX does not explicitly forbid the filename from including a
    (full or partial) path. If this setting is not set, any path part of *name*
    (and *x_opencti_additional_names*, if :attr:`SearchAdditionalFilenames`)
    will be part of the search.

    If :attr:`IncludeParentDirRef` is set, that path is included in the search.

    The file extension is not removed.
    """
    IncludeParentDirRef = "include-parent-dir-ref"
    """
    Include :stix:`Directory<#_lyvpga5hlw52>` path in *parent_directory_ref*
    (if any) in path when searching

    A File SCO may have a *parent directory* reference to a Directory. If this
    setting is enabled, and this reference exists, this directory's path will
    be part of the resulting search path. If this setting is set, and if the
    filename already includes a path and :attr:`BasenameOnly` is not set, the
    path in the filename is ignored.
    """


class DirSearchOptions(Enum):
    NormaliseSeparators = "normalise-separators"
    """

    """


class SearchConfig(ConfigBase):
    """
    FIXME
    """

    model_config = SettingsConfigDict(
        env_prefix="WAZUH_SEARCH_", validate_assignment=True
    )

    # common_options: set[CommonSearchOptions] = {
    #    CommonSearchOptions.AllowWildcard,
    #    CommonSearchOptions.AllowRegexp,
    # }
    # filesearch_options: set[FileSearchOption] = {
    #    FileSearchOption.SearchSize,
    #    FileSearchOption.IncludeParentDirRef,
    # }

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

    # TODO: search_agent_ip, search_agent_name, ignore_private_addrs
