import dateparser
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
from .opensearch_dsl import Match, OrderBy, QueryType
from .opensearch_dsl_helper import dsl_matches_from_string, dsl_order_by_from_string

T = TypeVar("T")

log = logging.getLogger(__name__)


class OpenSearchConfig(BaseSettings):
    """
    Configuration used for the opensearch module to connect to OpenSearch
    """

    model_config = SettingsConfigDict(
        env_prefix="WAZUH_OPENSEARCH_", validate_assignment=True
    )

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
    include_match: list[Match] | str | None = None
    """
    FIXME
    """
    exclude_match: list[Match] | str | None = "data.integration=opencti"
    """
    FIXME
    to a "bool" "must_not" array. The default value will exclude alerts
    produced by the `wazuh-opencti <https://github.com/misje/wazuh-opencti>`_
    Wazuh integration.
    """
    limit: int = Field(gt=0, default=50)
    """
    Maximum number of results to return from the OpenSearch alert query (after
    ordering by timestamp (and rule.level if :py:attr:`order_by_rule_level` is
    True)).
    """
    order_by: list[OrderBy] | str | None = "timestamp:desc"
    """
    How to order alert results before returning :py:attr:`limit` number of
    results. The default and recommended settings is to order by timestamp,
    descending, to get the most recent results. Alternatively, order alert by
    :wazuh:`alert rule level <ruleset/rules-classification.html>`, descending,
    then by timestamp, descending, in order to not miss any important alerts.

    Format:

        * timestamp:desc
        * rule.level:desc,timestamp:desc
    """
    filter: QueryType | None = None
    """
    Default filter used when searching

    All searches are performed with a :dsl:`Bool query <compound/bool>`. The
    members :attr:`search_after`, :attr:`include_match` and
    :attr:`exclude_match` are used in the Bool query's *filter*. FIXME
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

    @field_validator("include_match", "exclude_match", mode="before")
    @classmethod
    def parse_match_expression(
        cls, matches: list[Match] | str | None
    ) -> list[Match] | None:
        if isinstance(matches, str):
            return dsl_matches_from_string(matches)
        else:
            return matches

    @field_validator("order_by", mode="before")
    @classmethod
    def parser_order_by_expression(
        cls, order_by: list[OrderBy] | str | None
    ) -> list[OrderBy] | None:
        if isinstance(order_by, str):
            return dsl_order_by_from_string(order_by)
        else:
            return order_by
