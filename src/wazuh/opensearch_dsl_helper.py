from pydantic import BaseModel, Field

# from typing import Self # 3.11
from .opensearch_dsl import Match, OrderBy, QueryType, Regexp, Wildcard


def dsl_multi_regex(
    fields: list[str], regexp: str, case_insensitive: bool = False
) -> list[Regexp]:
    return [
        Regexp(field=field, query=regexp, case_insensitive=case_insensitive)
        for field in fields
    ]


def dsl_multi_wildcard(
    fields: list[str], query: str, case_insensitive: bool = False
) -> list[Wildcard]:
    return [
        Wildcard(field=field, query=query, case_insensitive=case_insensitive)
        for field in fields
    ]


# TODO: remove: no longer in used
def dsl_matches_from_string(terms: str, sep: str = "=") -> list[Match]:
    pairs = [term.split(sep) for term in terms.split(",")]
    if any(len(pair) != 2 for pair in pairs):
        raise ValueError(f'The terms string "{terms}" is invalid')

    return [Match(field=pair[0], query=pair[1]) for pair in pairs]


# TODO: remove: no longer in used
def dsl_order_by_from_string(terms: str, sep: str = ":") -> list[OrderBy]:
    pairs = [term.split(sep) for term in terms.split(",")]
    if any(len(pair) != 2 for pair in pairs):
        raise ValueError(f'The terms string "{terms}" is invalid')

    return [OrderBy(field=pair[0], order=pair[1]) for pair in pairs]


class QueryDefaults(BaseModel):
    filter: QueryType | None = None
    size: int | None = Field(gt=0, default=None)
    sort: list[OrderBy] = [OrderBy(field="timestamp", order="desc")]
