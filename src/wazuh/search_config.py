from pydantic import (
    Field,
    field_validator,
)
from pydantic_settings import SettingsConfigDict
from typing import TypeVar
from .utils import comma_string_to_set
from .config_base import ConfigBase
from enum import Enum


# class HashType(Enum):
#    SHA256 = ("SHA-256",)
#    SHA1 = ("SHA-1",)
#    MD5 = "MD5"


class FileSearchOption(Enum):
    """
    Options determining how to search for File SCOs
    """

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
    # FIXME: validate: CaseInsensitive requires AllowRegexp


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

    filesearch_options: set[FileSearchOption] = {
        FileSearchOption.SearchSize,
        FileSearchOption.SearchAdditionalFilenames,
        FileSearchOption.IncludeParentDirRef,
        FileSearchOption.IncludeRegValues,
        FileSearchOption.SearchFilenameOnly,
        FileSearchOption.AllowRegexp,
        FileSearchOption.CaseInsensitive,
    }

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