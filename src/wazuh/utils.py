import re
import ipaddress
from typing import Any, Callable, Literal
from os.path import commonprefix


def has(
    obj: dict,
    spec: list[str],
    value: Any = None,
    comp: Callable[[Any, Any], bool] | None = None,
) -> bool:
    """
    Test whether dict contains a specific structure

    Examples:
    >>> obj = {"a": {"b": 42}}
    >>> has(obj, ['a'])
    True
    >>> has(obj, ['b'])
    False
    >>> has(obj, ['a', 'b'])
    True
    >>> has(obj, ['a', 'b'], 43)
    False
    >>> has(obj, ['a', 'b'], 42)
    True
    """
    if not spec:
        if comp is not None and value is not None:
            return comp(obj, value)
        else:
            return obj == value if value is not None else True
    try:
        key, *rest = spec
        return has(obj[key], rest, value=value)
    except (KeyError, TypeError):
        return False


def has_any(obj: dict, spec1: list[str], spec2: list[str]) -> bool:
    """
    Test whether an object contains a specific structure

    Test whether obj contains a specific structure (a "JSON path") spec1. Then,
    test whether the resulting object has any of the keys listed in spec2.
    Example:

    >>> has_any({"a": {"b": {"d": 1, "e": 2}}}, ["a", "b"], ["c", "d"])
    True
    >>> # Because "a" exists, "b" exists in "a" and either "c" or "d" exists in
    >>> # "b"
    """
    if not spec1:
        return any(key in obj for key in spec2)
    try:
        key, *rest = spec1
        return has_any(obj[key], rest, spec2)
    except (KeyError, TypeError):
        return False


def has_atleast(obj: dict, *keys, threshold=1) -> bool:
    """
    Test whether at least N of keys are present in a dict

    Examples
    >>> has_atleast({'a': 1, 'b': 2}, 'a', 'c')
    True
    >>> has_atleast({'a': 1, 'b': 2}, 'a', 'b', 'c', threshold=2)
    True
    """
    return sum(key in obj for key in keys) >= threshold


def oneof(*keys: str, within: dict, default=None) -> Any:
    """
    Return the value of the first key that exists in the dict, or None.

    Examples:
    >>> oneof('foo', 'bar', within={'bar': 1, 'baz': 2})
    1
    >>> oneof('foo', 'bar', within={'baz': 42}, default=1)
    1
    """
    return next((within[key] for key in keys if key in within), default)


def oneof_nonempty(*keys: str, within: dict, default=None) -> Any:
    """
    Return the first truthly value of the first key that exists in the dict, or
    None.

    Examples:
    >>> oneof_nonempty('foo', 'bar', within={'foo': [], 'bar': 1})
    1
    >>> oneof_nonempty('bar', within={'foo': [], 'bar': None}, default=[])
    []
    >>> oneof_nonempty('baz', within={'foo': [], 'bar': None})
    """
    return next((within[key] for key in keys if key in within and within[key]), default)


def allof_nonempty(*keys: str, within: dict) -> list[Any]:
    """
    Return all non-empty values of keys found in dict.

    Examples:
    >>> allof_nonempty('foo', 'bar', 'baz', within={'foo': [], 'bar': 0, 'baz': 42})
    [42]
    """
    values = []
    for key in keys:
        if key in within:
            if isinstance(within[key], list):
                values += [val for val in within[key] if val]
            elif within[key]:
                values.append(within[key])

    return values


def first_or_none(values: list[Any]) -> Any | None:
    """
    Return the first value in the list, or None if the list is empty
    """
    return values[0] if values else None


def first_or_empty(values: list[str]) -> str:
    """
    Return the first value in the list or an empty string if the list is empty
    """
    return values[0] if values else ""


def re_search_or_none(pattern: str, string: str):
    """
    Return the regex match in the provided string, or None if the pattern is
    empty

    Examples:
    >>> re_search_or_none('(?<=foo=)bar', 'foo=bar')
    'bar'
    >>> re_search_or_none('(?<=foo=)bar', 'foo=baz')
    >>> re_search_or_none('', 'foo=bar')
    'foo=bar'
    """
    if not pattern:
        return string
    elif match := re.search(pattern, string):
        return match.group(0)
    else:
        return None


def extract_fields(
    obj: dict, fields: list[str], *, raise_if_missing: bool = True
) -> dict:
    """
    Extract values from a dict recursively using key paths

    ValueError will be raised if the path contains '*'. If raise_if_missing is
    True, no KeyError will be raised if a key is not found.

    Example:
    >>> extract_fields({ "a": { "b": { "c": 1 }}}, ["a.b.c", "a.b"])
    {'a.b.c': 1, 'a.b': {'c': 1}}
    """

    def traverse(obj: dict, keys: list[str]):
        for key in keys:
            try:
                obj = obj[key]
            except KeyError as e:
                if raise_if_missing:
                    raise e
                else:
                    return None

        return obj

    # Throw if the path contains the tmepting glob characther '*'. This
    # function does not recursively search for fields:
    if any("*" in field for field in fields):
        raise ValueError('Field cannot contain "*"')

    results = {field: traverse(obj, field.split(".")) for field in fields}
    # Remove Nones:
    return {k: v for k, v in results.items() if v is not None}


def search_fields(obj: dict, fields: list[str], *, regex: str = ""):
    """
    Search a dict for fields using key paths

    If the regex pattern is empty, this is the same as calling extract_fields() with raise_if_missing=False. Examples:

    >>> search_fields({'a': {'b': 'foo'}, 'c': 'bar'}, ['a.b', 'c'], regex='oo')
    {'a.b': 'oo'}
    >>> search_fields({'a': {'b': 'foo'}, 'c': 'bar'}, ['a.b', 'c'])
    {'a.b': 'foo', 'c': 'bar'}
    """
    return {
        k: match
        for k, v in extract_fields(obj, fields, raise_if_missing=False).items()
        for match in (re_search_or_none(regex, v),)
        if match is not None
    }


def search_field(obj: dict, field: str, *, regex: str = "") -> str | None:
    """
    Search a dict for a field using a key path

    Examples:
    >>> search_field({'a': {'b': 'foo'}, 'c': 'bar'}, 'a.b', regex='oo')
    'oo'
    >>> search_field({'a': {'b': 'foo'}, 'c': 'bar'}, 'c')
    'bar'
    """
    return search_fields(obj, [field], regex=regex).get(field)


def field_compare(
    obj: dict, fields: list[str], comp: Callable[[Any], bool] | Any
) -> bool:
    """
    Search for a value in a dict recursively using key paths

    Examples:
    >>> field_compare({'a': {'b': 1}, 'c': 2}, ['a.b', 'c'], lambda x: x > 1)
    True
    >>> # because 'c'→2 > 1, 'a.b'→1 is not
    >>> field_compare({'a': {'b': 1}, 'c': 2}, ['a.b', 'c'], 1)
    True
    >>> # because 'a.b' is 1
    """

    def _comp(field):
        return comp(field) if callable(comp) else field == comp

    return any(
        _comp(value)
        for value in extract_fields(obj, fields, raise_if_missing=False).values()
    )


def rule_level_to_severity(level: int):
    """
    Convert Wazuh alert level to OpenCTI incident severity

    Wazuh alert levels range from 1 to 15. OpenCTI incident severities are
    [low, medium, high, critical]. The mapping is done based off of the alert
    level description in the Wazuh documentation.
    """
    match level:
        case level if level in range(7, 10):
            return "medium"
        case level if level in range(11, 13):
            return "high"
        case level if level in range(14, 15):
            return "critical"
        case _:
            return "low"


def cvss3_to_severity(score: float):
    """
    Convert vulnerability CVSS3 score to incident severity
    """
    match score:
        case score if score > 9.0:
            return "critical"
        case score if score > 7.0:
            return "high"
        case score if score > 4.0:
            return "medium"
        case _:
            return "low"


def priority_from_severity(severity: str):
    """
    Map incident severity to a fitting incident priority
    """
    return {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}.get(
        severity, "P3"
    )


def severity_to_int(severity: str) -> int:
    """
    Map incident severity to an integer value
    """
    match severity:
        case "medium":
            return 1
        case "high":
            return 2
        case "critical":
            return 3
        # Put unknown severities in the same category as "low":
        case _:
            return 0


def max_severity(severities: list[str]):
    """
    Return the maximum incident severity, by mapping each value to an integer
    """
    return max(severities, key=lambda s: severity_to_int(s))


def common_prefix_string(strings: list[str], elideString: str = "[…]"):
    """
    Return a common prefix string from all strings, terminated by elideString

    Examples:
    >>> common_prefix_string(['You shall not', 'You shall indeed', "You shan't"])
    'You sha[…]'
    """
    if not strings:
        return ""
    if len(common := commonprefix(strings)) == len(strings[0]):
        return common
    else:
        return common + elideString


def list_or_empty(obj: dict, key: str):
    """
    Return list at the given key or an empty list if it does not exist.

    Examples:
    >>> list_or_empty({'a': [1, 2]}, 'a')
    [1, 2]
    >>> list_or_empty({}, 'a')
    []
    """
    return obj[key] if key in obj else []


def non_none(*args, threshold: int = 1) -> bool:
    """
    Require at least some of the arguments to be something other than None

    Examples:
    >> non_none(1, None, 3, threshold=2)
    True
    >> none_none(None, None):
    False
    """
    return sum(arg is not None for arg in args) >= threshold


def escape_lucene_regex(string: str):
    """
    Escape a string for all valid Lucene regex characters

    Example:
    >>> escape_lucene_regex('Benign string? Possibly. (*Perhaps not*)')
    'Benign string\\\\? Possibly\\\\. \\\\(\\\\*Perhaps not\\\\*\\\\)'
    """
    reg_chars = [".", "?", "+", "*", "|", "{", "}", "[", "]", "(", ")", '"', "\\"]
    return "".join("\\" + ch if ch in reg_chars else ch for ch in string)


def escape_path(path: str, *, count: int = 2):
    """
    Escape a path with backslashes, replacing every section of backslashes with
    more than two with the specified count.
    """
    return re.sub(r"\\{2,}", "\\" * count, path)


def search_in_object(obj: dict, search_term: str) -> dict[str, str]:
    """
    Search for a word in every value in a dict recursively

    The search method used is simply looking for a substring in any value that
    is a str instance. The returned dict contains paths (key.subkey.subsubkey)
    and values that matched.

    Examples:
    >>> search_in_object({'a': {'b': 'one two three', 'c': 'two'}}, 'two')
    {'a.b': 'one two three', 'a.c': 'two'}
    """

    def _search_in_obj(obj: dict, search_term: str, path: str = ""):
        if isinstance(obj, dict):
            return {
                path + "." + k if path else k: v
                for k, v in obj.items()
                if isinstance(v, str) and search_term in v
            } | {
                match_key: match_val
                for k, v in obj.items()
                for match_key, match_val in _search_in_obj(
                    v, search_term, path + "." + k if path else k
                ).items()
            }
        else:
            return {}

    return _search_in_obj(obj, search_term)


def search_in_object_multi(
    alert: dict, *search_terms: str, exclude_fields: list[str] = []
):
    """
    Search for multiple words in a dict recursively

    The search method used is simply looking for a substring in any value that
    is a str instance. The returned dict contains paths (key.subkey.subsubkey)
    and values that matched.

    Examples:
    >>> search_in_object_multi({'a': {'b': 'one two three', 'c': 'two', 'd': 'three'}}, 'two', 'three', exclude_fields=['a.d'])
    {'a.b': 'one two three', 'a.c': 'two'}
    """
    return {
        key: value
        for results in [search_in_object(alert, term) for term in search_terms]
        for key, value in results.items()
        if key not in exclude_fields
    }


def regex_transform(obj: dict[str, Any], map: dict[str, str]) -> dict[str, Any]:
    """
    Apply a regex tranformation to each key in object

    Each key in the map is a regular expression, and each value is the
    substitution pattern. The returned dict contains the substituted keys, and
    the original values from obj.

    Example:
    >>> regex_transform({'one.two': 1, 'three.one': 2}, {'^.+\\\\.(.+)$': '\\\\1'})
    {'two': 1, 'one': 2}
    """
    return {
        re.sub(pattern, replacement, key): value
        for key, value in obj.items()
        for pattern, replacement in map.items()
        if re.match(pattern, key)
    }


def ip_proto(addr: str) -> Literal["ipv4", "ipv6"] | None:
    """
    Return the literal 'ipv4' or 'ipv6' depending on the type of IP address, or
    None if the string is invalid.

    Example:
    >>> ip_proto('1.1.1.1')
    'ipv4'
    >>> ip_proto('::')
    'ipv6'
    >>> ip_proto('foo')
    """
    try:
        ip = ipaddress.ip_address(addr)
        if isinstance(ip, ipaddress.IPv4Address):
            return "ipv4"
        elif isinstance(ip, ipaddress.IPv6Address):
            return "ipv6"
        else:
            return None
    except ValueError:
        return None


def ip_protos(*addrs: str) -> list[str]:
    """
    Return a list of the literals, 'ipv4' or 'ipv6', for any valid IP addres

    Examples:
    >>> ip_protos('1.1.1.1', '::1', 'foo')
    ['ipv6', 'ipv4']
    >>> ip_protos('1.1.1.1', '8.8.8.8')
    ['ipv4']
    >>> ip_protos('foo', 'bar')
    []
    """
    return [
        result for result in {ip_proto(addr) for addr in addrs} if result is not None
    ]


# TODO: {src,dst}_ref should be a stix2.IPvxAddress type
def connection_string(
    *, src_ref=None, src_port=None, dst_ref=None, dst_port=None, protos: list[str] = []
):
    return (
        f"{':'.join(protos)} "
        f"{src_ref.value if src_ref else '?'}:{src_port if src_port is not None else '?'}"
        " → "
        f"{dst_ref.value if dst_ref else '?'}:{dst_port if dst_port is not None else '?'}"
    )
