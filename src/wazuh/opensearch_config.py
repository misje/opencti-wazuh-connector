import json
from datetime import datetime, timedelta
from pydantic import (
    AnyHttpUrl,
    AnyUrl,
    Field,
    field_validator,
)
from typing import Any
from pydantic_settings import SettingsConfigDict
from .utils import parse_human_datetime, truthy, verify_url
from .opensearch_dsl import Match, OrderBy, QueryType
from .opensearch_dsl_helper import dsl_matches_from_string, dsl_order_by_from_string
from .config_base import ConfigBase


class OpenSearchConfig(ConfigBase):
    """
    Configuration used for the opensearch module to connect to OpenSearch

    .. _search-filters:

    TODO: explain filters (include, exclude, filter). link to this section from settings

    add more information about opensearch?
    """

    model_config = SettingsConfigDict(
        env_prefix="WAZUH_OPENSEARCH_", validate_assignment=True
    )

    url: AnyHttpUrl
    """
    URL, including port and path, if neccessary, but must not include username
    and password

    .. note:: By default, OpenSearch runs on port 9200. This port must be
              specified in the URL unless the address on the specified scheme
              redirects or proxies the traffic.
    """
    username: str
    """
    A user that has necessary read-only permissions to alert indices

    See :ref:`create OpenSearch user <create-opensearch-user>` for a guide to
    create a user.
    """
    password: str
    """
    User password
    """
    verify_tls: bool = True
    """
    Verify the HTTPS certificate

    Disabling verification is highly discouraged. Use FIXME instead if the certificate is self-signed.
    """
    index: str = "wazuh-alerts-*"
    """
    Indices to search for Wazuh alerts
    """
    search_after: datetime | timedelta | None = None
    """
    Search for alerts in OpenSearch after this point in time, which may be
    specified either as a timestamp or a relative time (like "2 months ago")
    """
    include_match: list[Match] = []
    """
    FIXME
    """
    exclude_match: list[Match] = [Match(field="data.integration", query="opencti")]
    """
    FIXME
    to a "bool" "must_not" array. The default value will exclude alerts
    produced by the `wazuh-opencti <https://github.com/misje/wazuh-opencti>`_
    Wazuh integration.
    """
    limit: int = Field(gt=0, default=50)
    """
    Maximum number of results to return from the OpenSearch alert query (after
    ordering by timestamp (or your custom order, if :attr:`order_by` is
    overridden).
    """
    order_by: list[OrderBy] = [OrderBy(field="timestamp", order="desc")]
    """
    How to order alert results before returning :py:attr:`limit` number of
    results. The default and recommended settings is to order by timestamp,
    descending, to get the most recent results. Alternatively, order alert by
    :wazuh:`alert rule level <ruleset/rules-classification.html>`, descending,
    then by timestamp, descending, in order to not miss any important alerts.

    Alternative simple string format:

        * timestamp:desc
        * rule.level:desc,timestamp:desc
    """
    filter: list[QueryType] = []
    """
    Default filter used when searching

    All searches are performed with a :dsl:`Bool query <compound/bool>`. The
    members :attr:`search_after`, :attr:`include_match` and
    :attr:`exclude_match` are used in the Bool query's *filter* unless
    overriden by this setting. i.e. if this setting is non-empty, the values in
    :attr:`search_after`, :attr:`search_include` and :attr:`search_exclude` are
    ignored.

    When set as an environment variable, this setting must be specified as JSON.

    The implicit default filter (based on the settings mentioned) is

    .. code-block:: json

        [
            {
                "range": {
                    "@timestamp": {
                        "gte": "<timestamp>",
                    }
                }
            },
            {
                "bool": {
                    "must_not": [
                        {
                            "match": {
                                "data.integration": "opencti"
                            }
                        }
                    ]
                }
            }
        ]
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
        * Contain a host (TLD not required)

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
        cls, timestamp_str: datetime | timedelta | str | None
    ) -> datetime | timedelta | None:
        """
        Parse a timestamp-like string, either in an absolute or relative format

        Examples:

        >>> OpenSearchConfig.parse_lax_datetime(None)
        >>> OpenSearchConfig.parse_lax_datetime('2021-02-03')
        datetime.datetime(2021, 2, 3, 0, 0)
        >>> OpenSearchConfig.parse_lax_datetime('3 days ago')
        datetime.timedelta(days=3)
        >>> OpenSearchConfig.parse_lax_datetime('foo')
        Traceback (most recent call last):
        ValueError: timestamp is invalid
        """
        if timestamp_str is None:
            return None
        if isinstance(timestamp_str, (datetime, timedelta)):
            return timestamp_str

        if timestamp := parse_human_datetime(timestamp_str):
            return timestamp
        else:
            raise ValueError("timestamp is invalid")

    @field_validator("include_match", "exclude_match", mode="before")
    @classmethod
    def parse_match_expression(
        cls, matches: list[Match] | str | None
    ) -> list[Match] | None:
        if matches is None:
            return []
        if isinstance(matches, str):
            return dsl_matches_from_string(matches)
        else:
            return matches

    @field_validator("order_by", mode="before")
    @classmethod
    def parser_order_by_expression(cls, order_by: Any) -> list[OrderBy] | None:
        if order_by is None:
            return []
        if isinstance(order_by, str):
            return dsl_order_by_from_string(order_by)
        else:
            return order_by

    # TODO: move into a base class and inherit, along with model_config assignment
    def field_json(self, field: str) -> str:
        if not truthy(getattr(self, field)):
            return ""

        # This is super-ugly, but the initial model dump should be json in
        # order not to get proper serialisation of special types:
        return json.dumps(json.loads(self.model_dump_json(include={field}))[field])
