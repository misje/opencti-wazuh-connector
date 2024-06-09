import re
import ipaddress
import dateparser
from enum import Enum
from typing import Any, Callable, Literal, Mapping, Sequence, Type, TypeVar
from os.path import commonprefix
from pydantic import AnyUrl, ValidationError
from datetime import datetime, timedelta
from babel.dates import format_datetime, format_timedelta

T = TypeVar("T")
U = TypeVar("U")
EnumType = TypeVar("EnumType", bound=Enum)
Number = TypeVar("Number", int, float)
SimpleTypeType = TypeVar("SimpleTypeType", type(int), type(str), type(dict), type(list))
# TODO: use typevars to assert correct dict/mapping in and out of functions
Obj = TypeVar("Obj", bound=Mapping)

REGISTRY_PATH_REGEX = r"^(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HK(?:LM|CU|CR|U|CC))"
SID_REGEX = r"S-1-[0-59]-[0-9]{2}-[0-9]{8,10}-[0-9]{8,10}-[0-9]{8,10}-[1-9][0-9]{3,9}"


class SafeProxy:
    """
    Helper class that forwards member calls on a type if it is not None,
    otherwise just returns None

    This utility is useful when manipulating objects that may be None without
    having to catch exceptions or implemention guards.

    Examples:

    >>> SafeProxy('foo').upper()
    'FOO'
    >>> SafeProxy(None).upper()
    >>> SafeProxy({'foo': 'bar'}).get('foo', 'baz')
    'bar'
    >>> SafeProxy(None).get('foo', 'baz')
    """

    def __init__(self, value: Any | None):
        self.value = value

    def __getattr__(self, attr):
        if self.value is None:
            return lambda *args, **kwargs: None
        else:
            return getattr(self.value, attr)


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

    Examples:

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

    Examples:

    >>> has_atleast({'a': 1, 'b': 2}, 'a', 'c')
    True
    >>> has_atleast({'a': 1, 'b': 2}, 'a', 'b', 'c', threshold=2)
    True
    """
    return sum(key in obj for key in keys) >= threshold


def oneof(*keys: str, within: Mapping | None, default=None) -> Any:
    """
    Return the value of the first key that exists in the dict, or None.

    Examples:

    >>> oneof('foo', 'bar', within={'bar': 1, 'baz': 2})
    1
    >>> oneof('foo', 'bar', within={'baz': 42}, default=1)
    1
    """
    if not within:
        return default
    else:
        return next((within[key] for key in keys if key in within), default)


def oneof_nonempty(*keys: str, within: dict, default=None) -> Any:
    """
    Return the first truthly value of the first key that exists in the dict, or
    None.

    See :func:`truthy`

    Examples:

    >>> oneof_nonempty('foo', 'bar', within={'foo': [], 'bar': 1})
    1
    >>> oneof_nonempty('bar', within={'foo': [], 'bar': None}, default=[])
    []
    >>> oneof_nonempty('baz', within={'foo': [], 'bar': None})
    """
    return next(
        (within[key] for key in keys if key in within and truthy(within[key])), default
    )


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


def first_of(values: list[Any], item_type: type) -> Any:
    """
    Return the first item of the given type in the list

    Examples:

    >>> first_of([1, '2'], str)
    '2'
    >>> first_of([1, '2'], dict)
    """
    return first_or_none(list(filter(lambda x: isinstance(x, item_type), values)))


def truthy(value) -> bool:
    """
    Return the truthiness of a value unless it is a number, in which case
    return True
    """
    return True if isinstance(value, (int, float, complex)) else bool(value)


def filter_truthy(*values: Any) -> list[Any]:
    """
    Return a list of all items that are truthy (except numbers)

    See :func:`truthy`

    Examples:

    >>> filter_truthy(None)
    []
    >>> filter_truthy(None, 1, '', 0)
    [1, 0]
    """
    return list(filter(truthy, values))


def listify(value: T | list[T] | None) -> list[T]:
    """
    Return value if it is a list, otherwise return a single-item list

    Examples:

    >>> listify([1, 2])
    [1, 2]
    >>> listify(1)
    [1]
    """
    if value is None:
        return []

    return value if isinstance(value, list) else [value]


def re_search_or_none(pattern: str, string: str):
    """
    Return the regex match in the provided string, or return the search string
    if no pattern

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
    obj: Mapping, fields: list[str], *, raise_if_missing: bool = True
) -> dict:
    """
    Extract values from a dict recursively using key paths

    ValueError will be raised if the path contains '*'. If raise_if_missing is
    True, no KeyError will be raised if a key is not found.

    Examples:

    >>> extract_fields({ "a": { "b": { "c": 1 }}}, ["a.b.c", "a.b"])
    {'a.b.c': 1, 'a.b': {'c': 1}}
    """

    def traverse(obj: Mapping, keys: list[str]):
        for key in keys:
            try:
                obj = obj[key]
            except (KeyError, TypeError) as e:
                if raise_if_missing:
                    raise e from None
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


def extract_field(obj: Mapping, field: str, default: Any = None) -> Any:
    """
    Extract a value from a dict recursively using a key path

    Examples:

    >>> extract_field({'a': {'b': 1}}, 'a.b')
    1
    >>> extract_field({'a': {'b': 1}}, 'a.b.c')
    """
    return extract_fields(obj, [field], raise_if_missing=False).get(field, default)


def search_fields(obj: Mapping, fields: list[str], *, regex: str = "") -> dict:
    """
    Search a dict for fields using key paths

    If the regex pattern is empty, this is the same as calling extract_fields() with raise_if_missing=False. Examples:

    Examples:

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


# TODO: return value can be anything:
def search_field(obj: Mapping, field: str, *, regex: str = "") -> str | None:
    """
    Search a dict for a field using a key path

    Examples:

    >>> search_field({'a': {'b': 'foo'}, 'c': 'bar'}, 'a.b', regex='oo')
    'oo'
    >>> search_field({'a': {'b': 'foo'}, 'c': 'bar'}, 'c')
    'bar'
    """
    return search_fields(obj, [field], regex=regex).get(field)


def field_or_empty(
    obj: Mapping, field: str, default_type: SimpleTypeType = None
) -> Any:
    """
    Extract a field from an object or create a default value

    FIXME: more info

    Examples:

    >>> field_or_empty({'a': {'b': 1}}, 'a.b')
    1
    >>> field_or_empty({'a': {'b': 1}}, 'c', list)
    []
    >>> field_or_empty({'a': {'b': 1}}, 'c', str)
    ''
    >>> field_or_empty({'a': {'b': 1}}, 'd')
    Traceback (most recent call last):
    ValueError: Field d is not found, and no default type is specified
    """
    value = search_field(obj, field)
    default_values = {int: 0, str: "", dict: {}, list: []}
    if value is None:
        if default_type is None:
            raise ValueError(
                f"Field {field} is not found, and no default type is specified"
            )

        return default_values[default_type]
    else:
        return value


def field_or_default(obj: Mapping, field: str, default: Any) -> Any:
    """
    Return the result from search_field if there is a result, otherwise a
    default value

    Examples:

    >>> field_or_default({'a': {'b': 'foo'}}, 'a.b', 'bar')
    'foo'
    >>> field_or_default({'a': {'b': 'foo'}}, 'b.c', 'bar')
    'bar'
    """
    return result if (result := search_field(obj, field)) is not None else default


def field_as_list(obj: Mapping, field: str) -> list[Any]:
    """
    Return the result from search_field as a single-element list, or [] if no
    result

    Examples:

    >>> field_as_list({'a': {'b': 'foo'}}, 'a.b')
    ['foo']
    >>> field_as_list({}, 'a')
    []
    """
    return [result] if (result := search_field(obj, field)) is not None else []


def first_field(obj: dict, *fields: str, regex: str = "") -> Any:
    """
    Return the first field found in obj using search_field, or None

    Examples:

    >>> first_field({'a': {'b': 'foo'}, 'c': 'bar'}, 'a.b', 'c')
    'foo'
    >>> first_field({'a': {'b': 'foo'}, 'c': 'bar'}, 'a.c', 'c')
    'bar'
    >>> first_field({'a': {'b': 'foo'}, 'c': 'bar'}, 'd')
    """
    return next(
        (
            result
            for field in fields
            for result in (search_field(obj, field, regex=regex),)
            if result is not None
        ),
        None,
    )


def simplify_field_names(obj: dict) -> dict:
    """
    Remove the common prefix in all dict keys

    Examples:

    >>> simplify_field_names({'a.b.c': 1, 'a.b.d': 2, 'a.b.e': 3})
    {'c': 1, 'd': 2, 'e': 3}
    """
    common = common_prefix_string(list(obj.keys()), elideString="")
    return {key.replace(common, ""): value for key, value in obj.items()}


def compare_field(obj1: dict, obj2: dict, field: str) -> bool:
    """
    Compare a field in two nested dicts

    Examples:

    >>> compare_field({'a': {'b': 'foo'}}, {'a': {'b': 'foo'}}, 'a.b')
    True
    >>> compare_field({'a': {'b': 'foo'}}, {'a': 'bar'}, 'a.b')
    False
    >>> compare_field({'a': None}, {'a': None}, 'a')
    False
    """
    val1 = search_field(obj1, field)
    val2 = search_field(obj2, field)
    return val1 is not None and val2 is not None and val1 == val2


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


def cvss3_score_to_severity(score: float) -> str:
    """
    Convert vulnerability CVSS3 score to severity
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


def cvss3_severity_to_score(severity: str, *, default=0.0) -> float:
    """
    Convert vulnerability CVSS3 severity to score

    The middle value of the score range is used
    """
    match severity.lower():
        case "critical":
            return 9.5
        case "high":
            return 7.95
        case "medium":
            return 5.45
        case "low":
            return 2.0
        case _:
            return default


# TODO: This will break if case_priority_ov is customised by user. Make configurable in setting
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
    return max(severities, key=severity_to_int)


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

    The value at :paramref:`key` must be a list.

    Examples:

    >>> list_or_empty({'a': [1, 2]}, 'a')
    [1, 2]
    >>> list_or_empty({}, 'a')
    []
    """
    return obj[key] if key in obj else []


def lists_or_empty(obj: Mapping, *keys: str):
    """
    Return a concatenated list of all lists at the given keys

    If any of the keys do not exist, nothing happends. However, if the key
    exist, it must be a list.

    Examples:

    >>> lists_or_empty({'a': [1, 2], 'c': [3]}, 'a', 'b', 'c')
    [1, 2, 3]
    >>> lists_or_empty({}, 'a')
    []
    """
    return [
        item for key in keys if key in obj for items in (obj[key],) for item in items
    ]


def non_none(*args, threshold: int = 1) -> bool:
    """
    Require at least some of the arguments to be something other than None

    Examples:

    >>> non_none(1, None, 3, threshold=2)
    True
    >>> non_none(None, None)
    False
    """
    return sum(arg is not None for arg in args) >= threshold


def escape_lucene_regex(string: str):
    """
    Escape a string for all valid Lucene regex characters

    Examples:

    >>> escape_lucene_regex('Benign string? Possibly. (*Perhaps not*)')
    'Benign string\\\\? Possibly\\\\. \\\\(\\\\*Perhaps not\\\\*\\\\)'
    >>> escape_lucene_regex(r'foo\\bar\\\\baz')
    'foo\\\\\\\\bar\\\\\\\\baz'
    >>> escape_lucene_regex('\\\\foo\\\\\\\\bar')
    '\\\\\\\\foo\\\\\\\\bar'
    """
    reg_chars = [
        ".",
        "?",
        "+",
        "*",
        "|",
        "{",
        "}",
        "[",
        "]",
        "(",
        ")",
        '"',
        "~",
        "<",
        ">",
        "&",
        "@",
    ]
    # Replace any unescaped single backslashes:
    string = re.sub(r"(?<!\\)\\(?!\\)", r"\\\\", string)
    return "".join("\\" + ch if ch in reg_chars else ch for ch in string)


def escape_path(path: str, *, count: int = 2):
    """
    Escape a path with backslashes, replacing every section of backslashes with
    more than two with the specified count.

    Examples:

    >>> escape_path('foo\\\\bar\\\\\\\\baz\\\\\\\\\\\\\\\\qux')
    'foo\\\\bar\\\\baz\\\\qux'
    >>> escape_path('foo\\\\bar\\\\\\\\baz\\\\\\\\\\\\\\\\qux', count=4)
    'foo\\\\\\\\bar\\\\\\\\baz\\\\\\\\qux'
    """
    return re.sub(r"\\+", "\\" * count, path)


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
    alert: dict, *search_terms: str, exclude_fields: list[str] | None = None
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
    if exclude_fields is None:
        exclude_fields = []

    return {
        key: value
        for results in [search_in_object(alert, term) for term in search_terms]
        for key, value in results.items()
        if key not in exclude_fields
    }


def regex_transform_keys(obj: dict[str, T], transforms: dict[str, str]) -> dict[str, T]:
    """
    Apply a regex tranformation to each key in object

    Each key in the transforms map is a regular expression, and each value is
    the substitution pattern. The returned dict contains the substituted keys,
    and the original values from obj.

    Examples:

    >>> regex_transform_keys({'one.two': 1, 'three.one': 2}, {'^.+\\\\.(.+)$': '\\\\1'})
    {'two': 1, 'one': 2}
    """
    return {
        re.sub(pattern, replacement, key): value
        for key, value in obj.items()
        for pattern, replacement in transforms.items()
        if re.match(pattern, key)
    }


def ip_proto(addr: str) -> Literal["ipv4", "ipv6"] | None:
    """
    Return the literal 'ipv4' or 'ipv6' depending on the type of IP address, or
    None if the string is invalid.

    Examples:

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

    >>> sorted(ip_protos('1.1.1.1', '::1', 'foo'))
    ['ipv4', 'ipv6']
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
    *,
    src_ref=None,
    src_port=None,
    dst_ref=None,
    dst_port=None,
    protos: list[str] | None = None,
):
    return (
        f"{':'.join(protos or [])} "
        f"{src_ref.value if src_ref else '?'}:{src_port if src_port is not None else '?'}"
        " → "
        f"{dst_ref.value if dst_ref else '?'}:{dst_port if dst_port is not None else '?'}"
    )


def validate_mac(mac: str) -> bool:
    """
    Return true if the provided string is a valid MAC format

    Examples:

    >>> validate_mac('01:02:03:04:ab:CD')
    True
    >>> validate_mac('01-02-03-04-ab-CD')
    True
    >>> validate_mac('01:02-03:04-ab:CD')
    False
    >>> validate_mac('01020304abCD')
    True
    >>> validate_mac('0102.0304.abCD') # Cisco-style
    True
    """
    # Allow hyphons, colons or no separators, but require the separators to be
    # consistent. Or match a Cisco-style format:
    return bool(
        re.match(
            r"^(?:(?:[0-9A-Fa-f]{2}(?=([-:]|))(?:\1[0-9A-Fa-f]{2}){5}))$|^[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}$",
            mac,
        )
    )


def normalise_mac(mac: str) -> str:
    """
    Return a MAC with colons and loer-case characters

    The string must be a valid mac, otherwise an exception is possibly thrown.

    Examples:

    >>> normalise_mac('01:02:03:04:ab:CD')
    '01:02:03:04:ab:cd'
    >>> normalise_mac('01-02-03-04-ab-CD')
    '01:02:03:04:ab:cd'
    >>> normalise_mac('01:02-03:04-ab:CD')
    '01:02:03:04:ab:cd'
    >>> normalise_mac('01020304abCD')
    '01:02:03:04:ab:cd'
    >>> normalise_mac('0102.0304.abCD') # Cisco-style
    '01:02:03:04:ab:cd'
    """
    m = re.sub("[^0-9A-Fa-f]", "", mac).lower()
    return "%s:%s:%s:%s:%s:%s" % (m[0:2], m[2:4], m[4:6], m[6:8], m[8:10], m[10:12])


def mac_permutations(mac: str) -> list[str]:
    """
    Return MAC in different cases and styles (with or without colon, and
    Cisco-style)


    Examples:

    >>> mac_permutations('01:02:03:04:ab:CD')
    ['01:02:03:04:ab:cd', '01:02:03:04:AB:CD', '01020304abcd', '01020304ABCD', '0102.0304.abcd', '0102.0304.ABCD']
    """
    mac = normalise_mac(mac)
    no_sep = mac.replace(":", "")
    cisco = "%s.%s.%s" % (no_sep[0:4], no_sep[4:8], no_sep[8:12])
    return [
        mac,
        mac.upper(),
        no_sep,
        no_sep.upper(),
        cisco,
        cisco.upper(),
    ]


def parse_sha256(hashes_str: str) -> str | None:
    """
    Extract anything that looks like a SHA-256 hash from the string, or None

    Examples:

    >>> parse_sha256("SHA1=6E6BE6D81CB3B1E452F2AC0D7BEE162320A74DDA,MD5=4BB07B66D8D8DF05E437CF456FC7CCBC,SHA256=D4703A80CD98F93C6BC2CA04A92D994579D563541C35CD65776A5FE64AD385EE,IMPHASH=9646AFB1056B0472B325E82B3B78629D")
    'D4703A80CD98F93C6BC2CA04A92D994579D563541C35CD65776A5FE64AD385EE'
    """
    return (
        match.group(0) if (match := re.search("[A-Fa-f0-9]{64}", hashes_str)) else None
    )


def create_if(Object, *args, condition: Callable[[], bool], default=None, **kwargs):
    """
    Instantiate a class if a condition is met, otherwise return a default value

    Examples:

    >>> create_if(ipaddress.ip_address, '1.1.1.1', condition=lambda: True)
    IPv4Address('1.1.1.1')
    >>> create_if(ipaddress.ip_address, '1.1.1.1', condition=lambda: False)
    """
    return Object(*args, **kwargs) if condition() else default


def join_values(obj: dict, sep: str) -> str:
    """
    Join all values in a dict in order of keys

    Examples:

    >>> join_values({'b': 'bar', 'a': 'foo', 'c': 'baz'}, ' ')
    'foo bar baz'
    """
    return sep.join(value for _, value in sorted(obj.items()))


def merge_into(obj: dict, **overrides) -> dict:
    """
    Override items in a dict with named arguments

    Examples:

    >>> merge_into({'a': 1, 'b': 2}, b=42)
    {'a': 1, 'b': 42}
    """
    return obj | {key: value for key, value in overrides.items()}


def merge_outof(obj: dict, **overrides) -> dict:
    """
    Create a dict from the named arguments and override values from obj

    Examples:

    >>> merge_outof({'b': 42}, a=1, b=2)
    {'a': 1, 'b': 42}
    """
    return {key: value for key, value in overrides.items()} | obj


def is_registry_path(path: str) -> bool:
    """
    Is the provided path a registry path

    Examples:

    >>> is_registry_path('HKLM')
    True
    >>> is_registry_path('HKEY_LOCAL_MACHINE\\\\foo')
    True
    >>> is_registry_path('\\\\HKCU')
    False
    """
    return bool(
        re.search(
            REGISTRY_PATH_REGEX,
            path,
            flags=re.IGNORECASE,
        )
    )


def remove_reg_paths(obj: dict[T, str]) -> dict[T, str]:
    """
    Remove all registry paths from the dict values

    :func:`is_registry_path` is used.

    Examples:

    >>> remove_reg_paths({'a': '/foo/bar', 'b': 'HKEY_LOCAL_MACHINE/baz'})
    {'a': '/foo/bar'}
    """
    return {k: v for k, v in obj.items() if not is_registry_path(v)}


def reg_key_regexp(
    key: str, *, hive_aliases: bool, sid_ignore: bool, case_insensitive: bool
) -> str:
    """
    Return a regular expression string that matches varieties of the given key

    Examples:

    >>> reg_key_regexp('HKEY_LOCAL_MACHINE\\\\Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\VolatileUserMgrKey\\\\1\\\\S-1-5-21-3623811015-3361044348-30300820-1013', hive_aliases=True, sid_ignore=True, case_insensitive=True)
    '(HKEY_LOCAL_MACHINE|HKLM)\\\\Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\VolatileUserMgrKey\\\\1\\\\S-1-[0-59]-[0-9]{2}-[0-9]{8,10}-[0-9]{8,10}-[0-9]{8,10}-[1-9][0-9]{3,9}'
    >>> reg_key_regexp('HKEY_LOCAL_MACHINE\\\\Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\VolatileUserMgrKey\\\\1\\\\S-1-5-21-3623811015-3361044348-30300820-1013', hive_aliases=False, sid_ignore=True, case_insensitive=True)
    'HKEY_LOCAL_MACHINE\\\\Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\VolatileUserMgrKey\\\\1\\\\S-1-[0-59]-[0-9]{2}-[0-9]{8,10}-[0-9]{8,10}-[0-9]{8,10}-[1-9][0-9]{3,9}'
    >>> reg_key_regexp('HKEY_LOCAL_MACHINE\\\\Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\VolatileUserMgrKey\\\\1\\\\S-1-5-21-3623811015-3361044348-30300820-1013', hive_aliases=True, sid_ignore=False, case_insensitive=True)
    '(HKEY_LOCAL_MACHINE|HKLM)\\\\Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\VolatileUserMgrKey\\\\1\\\\S-1-5-21-3623811015-3361044348-30300820-1013'
    """
    transforms: dict[str, str] = {
        "^(?:HKEY_LOCAL_MACHINE|HKLM)": "(HKEY_LOCAL_MACHINE|HKLM)",
        "^(?:HKEY_CURRENT_USER|HKCU)": "(HKEY_CURRENT_USER|CU)",
        "^(?:HKEY_CLASSES_ROOT|HKCR)": "(HKEY_CLASSES_ROOT|CR)",
        "^(?:HKEY_USERS|HKU)": "(HKEY_USERS|HKU)",
        "^(?:HKEY_CURRENT_CONFIG|HKCC)": "(HKEY_CURRENT_CONFIG|HKCC)",
    }
    if hive_aliases:
        for search, replace in transforms.items():
            key = re.sub(search, replace, key, re.IGNORECASE if case_insensitive else 0)
    if sid_ignore:
        key = re.sub(SID_REGEX, SID_REGEX, key)

    return key


def comma_string_to_set(
    values: Any, EType: Type[EnumType] | None = None
) -> set[str] | set[EnumType]:
    """
    Split a comma-separated string to a set

    This function only splits a string into a set of strings. Further
    validation and coersion is left to pydantic or other validators. Empty
    strings returns empty sets. The special string "all" returns a
    ``set(Type)`` if :paramref:`EType` is specified, as a convenient way to
    return a set with all possible enum values.

    Note that a set of enum values are only only return when :paramref:`EType`
    is set and when :paramref:`values` is "all". Otherwise, a set of strings is
    returned. Converting these values to enum values is left for pydantic to
    validate.

    Examples:

    >>> sorted(comma_string_to_set('foo,bar, foo'))
    ['bar', 'foo']
    >>> class FooEnum(Enum):
    ...   Foo = 'foo'
    ...   Bar = 'bar'
    >>> all = {FooEnum.Foo, FooEnum.Bar}
    >>> comma_string_to_set('all', FooEnum) == all
    True
    """
    if isinstance(values, str):
        if not values:
            return set()
        elif EType is not None and values == "all":
            return set(EType)
        else:
            # If this is a string, parse it as a comma-separated string with
            # enum values:
            return {type_str for type_str in re.split(r",\s*", values)}
    else:
        # Otherwise, let pydantic validate whatever it is:
        return values


def none_unless_threshold(
    value: Number, threshold: Number, default: Number | None = None
) -> Number | None:
    """
    Return value if it is a number and above or equals a threshold, otherwise default


    Examples

    >>> none_unless_threshold(1, 2, -1)
    -1
    >>> none_unless_threshold(1, 2)
    >>> none_unless_threshold(None, 2, 3)
    3
    >>> none_unless_threshold(2, 2)
    2
    """
    return value if isinstance(value, (int, float)) and value >= threshold else default


def verify_url(
    url: AnyUrl | str | None,
    *,
    must: Sequence[str] | None = None,
    must_not: Sequence[str] | None = ("username", "password", "query", "fragment"),
    throw: bool = False,
) -> bool:
    """
    Verify that a URL conforms to a set of requirement

    :param url:      An AnyUrl object or any of its specialised types, None, or
                     a string. If the parameter is a string, an AnyUrl is
                     created (using default constraints).
    :param must:     Set of properties that must be set (i.e. not None) in the
                     :paramref:`url`. The properties must exist.
    :param must_not: Set of properties that must not be set (i.e. None) in the
                     :paramref:`url`. The properties must exist.
    :param throw:    Raise an exception if :paramref:`url` is a string and the
                     AnyUrl created from this argument raises a
                     ValidationError, or if the properties check fail.

    This function's purpose is to run additional checks on an AnyUrl object or
    any of its specialised types, like HttpUrl, MySQLDsn etc. It's useful to
    ensure that credentials are not part of the URL, and that its default
    arguments ensure that username, password, query and fragment are not set.

    Although :paramref:`url` may be a string, it's highly recommended to use
    one of pydantic's URL classes instead, in order to use suitable
    UrlConstraints in addition to the checks in this function.

    :return:

        * True if
            * the properties in :paramref:`must` are not None in
              :paramref:`url`
            * the properties in :paramref:`must_not` are None in
              :paramref:`url`
        * False if the above is not true, or if :paramref:`url` is None

    :raises ValueError: If :paramref:`throw` is true (see :paramref:`throw`),
                        or if :paramref:`must` or :paramref:`must_not` contians
                        properties that do not exist in AnyUrl.

    Examples:

    >>> verify_url('foo', throw=True)
    Traceback (most recent call last):
    ValueError: Invalid URL
    >>> verify_url('http://foo.bar/baz')
    True
    >>> verify_url('http://user:pass@foo.bar')
    False
    >>> verify_url('http://user:@foo.bar', must_not=['password'])
    True
    >>> from pydantic import AnyHttpUrl
    >>> verify_url(AnyHttpUrl('http://foo.bar/baz'))
    True
    """
    # FIXME: somehow doesn't work:
    # >>> verify_url('foo://bar', must=['port'], throw=True)
    # Traceback (most recent call last):
    # ValueError: Invalid URL: properties not set: port
    # >>> verify_url(AnyHttpUrl('http://foo.bar/baz?qux=quux'), throw=True)
    # Traceback (most recent call last):
    # ValueError: Invalid URL: properties expected to be empty: query
    if must is None:
        must = []
    if must_not is None:
        must_not = []

    if isinstance(url, str):
        try:
            url = AnyUrl(url)
        except ValidationError as e:
            if throw:
                raise ValueError("Invalid URL") from e
            else:
                return False

    elif not isinstance(url, AnyUrl):
        return False

    valid = all(getattr(url, prop) is not None for prop in must) and all(
        getattr(url, prop) is None for prop in must_not
    )
    if not throw:
        return valid
    # Provide helpful exception info when used in pydantic validators:
    elif not valid and (
        failed_musts := [prop for prop in must if getattr(url, prop) is None]
    ):
        raise ValueError(f"Invalid URL: properties not set: {', '.join(failed_musts)} ")
    elif not valid and (
        failed_mustnts := [prop for prop in must_not if getattr(url, prop) is not None]
    ):
        raise ValueError(
            f"Invalid URL: properties expected to be empty: {', '.join(failed_mustnts)} "
        )
    else:
        return True


def remove_empties(
    value: Any,
    is_empty: Callable[[Any], bool] = lambda x: False
    if isinstance(x, (bool, int))
    else not bool(x),
) -> Any:
    """

    Examples:

    >>> remove_empties({'a': {}, 'b': {'c': 0, 'd': 1}, 'e': [False, None, [], {}]})
    {'b': {'c': 0, 'd': 1}, 'e': [False]}
    >>> remove_empties({'a': None, 'b': {'c': 0, 'd': None}, 'e': [3, None]}, lambda x: x is None)
    {'b': {'c': 0}, 'e': [3]}
    """
    if isinstance(value, list):
        return [
            x for x in (remove_empties(x, is_empty) for x in value) if not is_empty(x)
        ]
    elif isinstance(value, dict):
        return {
            key: val
            for key, val in (
                (key, remove_empties(val, is_empty)) for key, val in value.items()
            )
            if not is_empty(val)
        }
    else:
        return value


def remove_nones(obj: Mapping) -> dict:
    """
    Remove all Nones from a dict

    Nulls are not removed recursively. See also :attr:`remove_empties`.

    Example:

    >>> remove_nones({'a': 1, 'b': None})
    {'a': 1}
    """
    return {key: value for key, value in obj.items() if value is not None}


def parse_human_datetime(timestamp: str) -> datetime | timedelta | None:
    """
    Parse a string containing a date, time or interval into a
    datetime/timedelta object

    Examples:

    >>> parse_human_datetime('2024-01-01 14:42')
    datetime.datetime(2024, 1, 1, 14, 42)
    >>> d1 = parse_human_datetime('3 days ago')
    >>> d2 = parse_human_datetime('3 days ago')
    >>> d1 == d2 == timedelta(days=3)
    True
    """
    # Use an anchor in order to reliably calculate a timedelta:
    anchor = datetime.now()
    parsed = dateparser.parse(timestamp, settings={"RELATIVE_BASE": anchor})
    if parsed is None:
        return None

    # In order to distinguish datetimes and timedeltas, parse the string again
    # with a different anchor. If the result is the same, do not calculate a
    # delta:
    parsed2 = dateparser.parse(
        timestamp, settings={"RELATIVE_BASE": anchor + timedelta(seconds=1)}
    )
    if parsed2 == parsed:
        return parsed

    return anchor - parsed


def del_key(key: T, obj: dict[T, U]) -> dict[T, U]:
    """
    Remove a key from a dict and return the new dict

    Examples:

    >>> del_key('foo', {'foo': 'bar', 'baz': 'qux'})
    {'baz': 'qux'}
    """
    del obj[key]
    return obj


# TODO: find a way to override locale for tests (setlocale doesn't work)
def datetime_string(timestamp: datetime | timedelta | None, default="–") -> str:
    """
    FIXME

    Examples:

    >>> datetime_string(datetime(2024, 1, 2, 3, 4, 5))
    'Jan 2, 2024, 3:04:05\u202fAM'
    >>> datetime_string(timedelta(seconds=42))
    '42 seconds'
    """
    if isinstance(timestamp, datetime):
        return format_datetime(timestamp)
    elif isinstance(timestamp, timedelta):
        return format_timedelta(timestamp)
    else:
        return default


def in_str_list(
    value: str | tuple[str, ...], str_list: str, *, sep_regex: str = r",\s*"
) -> bool:
    """
    Is a string within a list represented as a list

    Examples:

    >>> in_str_list('foo', 'foo, bar')
    True
    >>> in_str_list('foo', 'foo,bar')
    True
    >>> in_str_list('baz', 'foo,bar')
    False
    >>> in_str_list('baz', 'foo bar   baz', sep_regex='\\\\s+')
    True
    >>> in_str_list(('foo', 'bar'), 'qux,bar')
    True
    """
    values = re.split(sep_regex, str_list)
    if isinstance(value, tuple):
        return any(candidate in values for candidate in value)
    else:
        return value in values


def is_enum_set(value: Any) -> bool:
    """
    Examples:

    >>> class Foo(Enum):
    ...   Bar = 'bar'
    ...   Baz = 'baz'
    >>> qux = {Foo.Bar, Foo.Baz}
    >>> is_enum_set(qux)
    True
    >>> is_enum_set(set())
    True
    >>> is_enum_set(set('foo'))
    False
    """
    return isinstance(value, set) and all(
        issubclass(type(item), Enum) for item in value
    )


def float_or_none(value: str | None, *, accept_invalid=False) -> float | None:
    """
    Return string as float unless it is null, then return null

    Examples:

    >>> float_or_none('123.4')
    123.4
    >>> float_or_none(None)
    >>> float_or_none('foo')
    Traceback (most recent call last):
    ValueError: could not convert string to float: 'foo'
    >>> float_or_none('foo', accept_invalid=True)
    """
    try:
        return float(value) if value is not None else None
    except ValueError as e:
        if accept_invalid:
            return None
        else:
            raise e from None


def get_path_sep(path: str) -> str:
    """
    Determine path separator used in a string

    A very simple approach is used.

    Examples:

    >>> get_path_sep('/')
    '/'
    >>> get_path_sep('foo/bar')
    '/'
    >>> get_path_sep('C\\\\Windows')
    '\\\\'
    """
    return "\\" if ":\\" in path or path.count("\\") >= 1 else "/"


def dict_member_list_first_or_remove(values: dict) -> dict:
    """
    If a key contains a list, replace value with the first item in list, or
    remove the key

    Examples:

    >>> dict_member_list_first_or_remove({'a': 'b', 'c': ['d'], 'e': []})
    {'a': 'b', 'c': 'd'}
    """
    return remove_empties(
        {
            key: item
            for key, items in values.items()
            for item in (first_or_none(items) if isinstance(items, list) else items,)
        }
    )


def remove_host_from_uri(uri: str) -> str:
    """
    Remove scheme and host from URI

    Examples:

    >>> remove_host_from_uri('http://foo.bar/baz?qux')
    '/baz?qux'
    >>> remove_host_from_uri('foo.bar/baz')
    '/baz'
    """
    return re.sub(r"^(?:.+://)?[^/]+(?=/)", "", uri)


def raises(func: Callable[[], Any]) -> bool:
    """
    Return true if the callback raises an exception

    Examples:

    >>> raises(lambda: 1/0)
    True
    >>> raises(lambda: 'foo')
    False
    """
    try:
        func()
        return False
    except Exception:
        return True
