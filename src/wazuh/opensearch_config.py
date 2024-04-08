import dateparser
import json
import logging
from datetime import datetime
from pydantic import (
    AnyHttpUrl,
    AnyUrl,
    Field,
    field_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import TypeVar
from .utils import verify_url

T = TypeVar("T")

log = logging.getLogger(__name__)


class OpenSearchConfig(BaseSettings):
    """
    Configuration used for the opensearch module to connect to OpenSearch
    """

    model_config = SettingsConfigDict(
        env_prefix="WAZUH_OPENSEARCH_", validate_assignment=True
    )

    # class Order(Enum):
    #    ASC = "asc"
    #    DESC = "desc"

    # class OrderBy(BaseModel):
    #    field: str
    #    order: Order

    url: AnyHttpUrl | str
    """
    URL, including port and path, if neccessary, but must not include username
    and password

    .. note:: By default, OpenSearch runs on port 9200. This port must be
              specified in the URL unless the address on the specified scheme
              redirects or proxies the traffic.
    """
    username: str
    """
    A user that has FIXME permissions
    """
    password: str
    """
    User password
    """
    index: str = "wazuh-alerts-*"
    """
    Indices to search for Wazuh alerts
    """
    search_after: datetime | None = None
    """
    Search for alerts in OpenSearch after this point in time, which may be
    specified either as a timestamp or a relative time (like "2 months ago")
    """
    # TODO: filter?
    include_match: list | str | None = None
    """
    Search query to include in all OpenSearch alert searches. It may either be
    a DSL json object, or alternatively a comma-separated string with key=value
    items that will be transformed into a number of full-text "match" query. In
    both cases, the query will be added to a "bool" "must" array.
    """
    exclude_match: list | str | None = "data.integration=opencti"
    """
    Search query to include in all OpenSearch alert searches to exclude
    results. It may either be a DSL json object, or alternatively a
    comma-separated string with key=value items that will be transformed into a
    number of full-text "match" query. In both cases, the query will be added
    to a "bool" "must_not" array. The default value will exclude alerts
    produced by the `wazuh-opencti <https://github.com/misje/wazuh-opencti>`_
    Wazuh integration.
    """
    # filter: list[str]
    limit: int = Field(gt=0, default=50)
    """
    Maximum number of results to return from the OpenSearch alert query (after
    ordering by timestamp (and rule.level if :py:attr:`order_by_rule_level` is
    True)).
    """
    order_by: list[dict[str, dict[str, str]]] | str = "timestamp=desc"
    """
    How to order alert results before returning :py:attr:`limit` number of
    results. The default and recommended settings is to order by timestamp,
    descending, to get the most recent results. Alternatively, order alert by
    :wazuh:`alert rule level <ruleset/rules-classification.html>`, descending,
    then by timestamp, descending, in order to not miss any important alerts.

    Format:

        * timestamp=desc
        * rule.level=desc,timestamp=desc
    """

    @field_validator("url", mode="before")
    @classmethod
    def parse_http_url(cls, url: str | AnyHttpUrl) -> AnyHttpUrl:
        """
        Convert a URL string to a AnyHttpUrl
        """
        return url if isinstance(url, AnyUrl) else AnyHttpUrl(url)

    @field_validator("url", mode="after")
    @classmethod
    def validate_http_url(cls, url: AnyHttpUrl) -> AnyHttpUrl:
        """
        Verify that a HTTP URL does not contain unexpected properties

        The URL must

        * Contain the schemes http or https
        * Contain a host (TLP not required)

        and must not

        * Contain a username (set in :attr:`username` instead)
        * Contain a password (set in :attr:`password` instead)
        * Contain a query or fragments
        """
        verify_url(url, throw=True)
        return url

    @field_validator("search_after", mode="before")
    @classmethod
    def parse_lax_datetime(
        cls, timestamp_str: datetime | str | None
    ) -> datetime | None:
        """
        Parse a timestamp-like string, either in an absolute or relative format

        Examples:

        >>> Config.parse_lax_datetime(None)
        >>> Config.parse_lax_datetime('2021-02-03')
        datetime.datetime(2021, 2, 3, 0, 0)

        TODO: test for relative times
        """
        if timestamp_str is None:
            return None
        if isinstance(timestamp_str, datetime):
            return timestamp_str

        if timestamp := dateparser.parse(timestamp_str):
            return timestamp
        else:
            raise ValueError("timestamp is invalid")

    @field_validator("include_match", "exclude_match", mode="after")
    @classmethod
    def parse_match_patterns(cls, patterns_str: str | None) -> list | None:
        """
        Parse a string with comma-separated key–value pairs in a list of
        OpenSearch DSL match query JSON objects

        If the string is a valid JSON array, it is passed on and assumed to be
        valid DSL.

        Examples:

        >>> Config.parse_match_patterns("foo=bar,baz=qux")
        [{'match': {'foo': 'bar'}}, {'match': {'baz': 'qux'}}]
        """
        if patterns_str is None:
            return None

        # Do not obther at all to try to validate DSL. If it is valid JSON,
        # just let the opensearch module attempt to use it:
        try:
            dsl = json.loads(patterns_str)
            if isinstance(dsl, list):
                return dsl
        except json.JSONDecodeError:
            pass

        # Otherwise, ensure that the string contains a list of key–value pairs
        pairs = [pattern.split("=") for pattern in patterns_str.split(",")]
        if any(len(pair) != 2 for pair in pairs):
            raise ValueError(f'The search patterns string "{patterns_str}" is invalid')

        return [{"match": {pair[0]: pair[1]}} for pair in pairs]

    @field_validator("order_by", mode="before")
    @classmethod
    def parse_order_by(cls, order_by: str) -> list[dict[str, dict[str, str]]]:
        def verify_order(order: str):
            if order.lower() not in ["asc", "desc"]:
                raise ValueError(f"Order not one of [ASC, DESC]: {order}")

            return True

        try:
            return [
                {field: {"order": order}}
                for item in order_by.split(",")
                for field, order in (item.split("="),)
                if verify_order(order)
            ]
        except ValueError:
            raise ValueError(
                "order_by must be a comma-separated list of <field>:<order>"
            )
