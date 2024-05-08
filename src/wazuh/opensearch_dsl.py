from __future__ import annotations
from collections.abc import Sequence
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_serializer,
    model_validator,
)
from typing import Any, TypeAlias
from enum import Enum

from wazuh.utils import del_key

# TODO: remove boost (any param, actually) if default value
# TODO: Perhaps an empty query is allowed, but when it is removed by
# exclude_none/exclude_unset, it produces an invalid query. Validate here or in
# opensearch?


class Term(BaseModel):
    model_config = ConfigDict(validate_assignment=True)
    field: str
    value: str
    case_insensitive: bool = False
    boost: float = Field(ge=0.0, default=1.0)

    @model_serializer
    def serialise(self) -> dict[str, Any]:
        if type(self).__name__ != "Term":
            return self.model_dump()
        return {
            "term": {
                self.field: self.value,
                "case_insensitive": self.case_insensitive,
                "boost": self.boost,
            }
        }


class Exists(BaseModel):
    model_config = ConfigDict(validate_assignment=True)
    field: str
    boost: float = Field(ge=0.0, default=1.0)

    @model_serializer
    def serialise(self) -> dict[str, Any]:
        if type(self).__name__ != "Exists":
            return self.model_dump()
        return {
            "exists": {
                "field": self.field,
                "boost": self.boost,
            }
        }


class Range(BaseModel):
    model_config = ConfigDict(validate_assignment=True)
    field: str
    gte: Any = None
    gt: Any = None
    lte: Any = None
    lt: Any = None
    boost: float = Field(ge=0.0, default=1.0)

    @model_validator(mode="after")
    def require_something(self) -> Range:
        assert self.field and any(
            getattr(self, prop) is not None for prop in ["gte", "gt", "lte", "lt"]
        )
        return self

    @model_serializer(mode="wrap")
    def serialise(self, handler) -> dict[str, Any]:
        if type(self).__name__ != "Range":
            return self.model_dump()

        return {
            type(self).__name__.lower(): {
                self.field: {**del_key("field", handler(self))}
            }
        }


class Match(BaseModel):
    model_config = ConfigDict(validate_assignment=True)
    field: str
    query: str

    @model_serializer
    def serialise(self) -> dict[str, Any]:
        if type(self).__name__ != "Match":
            return self.model_dump()
        return {"match": {self.field: self.query}}


class MultiMatch(BaseModel):
    model_config = ConfigDict(validate_assignment=True)
    query: str
    fields: list[str]

    @model_serializer
    def serialise(self) -> dict[str, Any]:
        if type(self).__name__ != "MultiMatch":
            return self.model_dump()
        return {"multi_match": {"query": self.query, "fields": self.fields}}


class _Globby(BaseModel):
    model_config = ConfigDict(validate_assignment=True, populate_by_name=True)
    field: str
    query: str
    case_insensitive: bool = False

    @field_validator("field")
    @classmethod
    def validate_field(cls, field):
        if "*" in field:
            raise ValueError('Field name cannot contain a glob ("*")')

        return field

    @model_serializer
    def serialise(self) -> dict[str, Any]:
        print(f"Calling serialiser for {type(self).__name__}")
        # Due to what seems like a bug in pydantic (no issue yet), Bool calls
        # this serializer for some reason:
        if type(self).__name__ not in ("Wildcard", "Regexp"):
            return self.model_dump()

        return {
            type(self).__name__.lower(): {
                self.field: {
                    "value": self.query,
                    "case_insensitive": self.case_insensitive,
                }
            }
        }


class Wildcard(_Globby):
    pass


class Regexp(_Globby):
    pass


class Bool(BaseModel):
    model_config = ConfigDict(validate_assignment=True)
    must: Sequence[
        Term | Exists | Range | Match | MultiMatch | Wildcard | Regexp | Bool
    ] = []
    must_not: Sequence[
        Term | Exists | Range | Match | MultiMatch | Wildcard | Regexp | Bool
    ] = []
    should: Sequence[
        Term | Exists | Range | Match | MultiMatch | Wildcard | Regexp | Bool
    ] = []
    filter: Sequence[
        Term | Exists | Range | Match | MultiMatch | Wildcard | Regexp | Bool
    ] = []
    minimum_should_match: int | None = None

    @model_validator(mode="after")
    def require_something(self) -> Bool:
        assert any(
            getattr(self, prop) for prop in ["must", "must_not", "should", "filter"]
        )
        if self.should and self.minimum_should_match is None:
            self.minimum_should_match = 1

        return self

    @model_serializer(mode="wrap")
    def serialise(self, handler) -> dict[str, Any]:
        return {type(self).__name__.lower(): handler(self)}


# Cannot be used in Bool, unfortunately, due to self-referencing:
QueryType: TypeAlias = (
    Term | Exists | Range | Match | MultiMatch | Wildcard | Regexp | Bool
)


class SortOrder(Enum):
    Asc = "asc"
    Desc = "desc"


class OrderBy(BaseModel):
    model_config = ConfigDict(validate_assignment=True)
    field: str
    order: SortOrder | str

    @field_validator("order", mode="before")
    @classmethod
    def parse_order(cls, order: SortOrder | str) -> SortOrder:
        return order if isinstance(order, SortOrder) else SortOrder(order)

    @model_serializer
    def serialise(self) -> dict[str, Any]:
        return {self.field: {"order": self.order}}


class Query(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    query: QueryType
    size: int | None = Field(gt=0, default=None)
    sort: list[OrderBy] = []
