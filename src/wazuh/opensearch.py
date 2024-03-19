import urllib3
import requests
from datetime import datetime
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from urllib.parse import urljoin


class OpenSearchClient:
    """
    Simple OpenSearch search SDK
    """

    class ConnectionError(Exception):
        def __init__(self, message):
            super().__init__(message)

    class ParseError(Exception):
        def __init__(self, message):
            super().__init__(message)

    class QueryError(Exception):
        def __init__(self, message):
            super().__init__(message)

    def __init__(
        self,
        *,
        helper: OpenCTIConnectorHelper,
        url: str,
        username: str,
        password: str,
        limit: int,
        index: str,
        filters: list[dict[str, dict]] = [],
        search_after: datetime | None,
        order_by: list[dict] = [],
        include_match: list[dict] | None,
        exclude_match: list[dict] | None,
    ) -> None:
        self.url = url
        self.username = username
        self.password = password
        self.index = index
        self.limit = limit
        self.helper = helper
        self.filters = filters
        self.search_after = search_after
        self.order_by = self._parse_order_by(order_by)
        self.include_match = include_match
        self.exclude_match = exclude_match

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @staticmethod
    def _parse_order_by(order_by: list[dict]):
        def _validate_order(field, order):
            if not isinstance(field, str):
                raise OpenSearchClient.QueryError("order-by field must be a string")
            if not (isinstance(order, str) and order.lower() in ["asc", "desc"]):
                raise OpenSearchClient.QueryError("order-by order must be [ASC, DESC]")
            return True

        return [
            {field: {"order": order}}
            for item in order_by
            # This dict should only have on key, but accept sevaral anyway
            # since it works despite making less sense (no defined orer):
            for field, order in item.items()
            if _validate_order(field, order)
        ]

    def _query(self, endpoint, query):
        adapter = HTTPAdapter(
            max_retries=Retry(
                total=3,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "OPTIONS"],
            )
        )
        http = requests.Session()
        http.auth = (self.username, self.password)
        http.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        http.mount(self.url, adapter)
        # TODO:: allow import of cert
        http.verify = False

        try:
            response = http.get(
                urljoin(self.url, endpoint),
                json=query,
            )
            response.raise_for_status()

            return response.json()

        except requests.JSONDecodeError as e:
            raise self.ParseError(f"Failed to parse JSON response: {e}")
        except requests.exceptions.RequestException as e:
            raise self.ConnectionError(f"Failed to connect to {self.url}: {e}")

    def _search(self, query: dict):
        query = {
            "query": query,
            "size": self.limit,
            "sort": self.order_by + [{"timestamp": {"order": "desc"}}],
        }
        self.helper.connector_logger.debug(f'Sending query "{query}"')

        r = self._query(f"{self.index}/_search", query=query)
        if not r:
            return None
        try:
            if r["timed_out"]:
                self.helper.connector_logger.warning("OpenSearch: Query timed out")
                self.helper.connector_logger.debug(
                    "OpenSearh: Searched {}/{} shards, {} skipped, {} failed".format(
                        r["_shards"]["successful"],
                        r["_shards"]["total"],
                        r["_shards"]["skipped"],
                        r["_shards"]["failed"],
                    )
                )
            if r["hits"]["total"]["value"] > self.limit:
                self.helper.connector_logger.warning(
                    "Processing only {} of {} hits (hint: increase 'max_hits')".format(
                        self.limit, r["hits"]["total"]["value"]
                    )
                )

            return r

        except (IndexError, KeyError):
            raise self.ParseError("Failed to parse result: Unexpected JSON structure")

    def search(
        self,
        must: dict | list[dict] | None = None,
        must_not: dict | list[dict] | None = None,
        should: dict | list[dict] | None = None,
    ):
        if not must and not must_not and not should:
            raise self.QueryError("One of must, must_not and should must be non-empty")

        # For convenience, allow caller to specify either an object or a list:
        must = must if isinstance(must, list) else [must] if must else []
        should = should if isinstance(should, list) else [should] if should else []
        must_not = (
            must_not if isinstance(must_not, list) else [must_not] if must_not else []
        )

        # include the convenience global filters :
        must = must + (self.include_match or [])
        must_not = must_not + (self.exclude_match or [])

        filter = self.filters
        if self.search_after:
            filter.insert(
                0,
                {"range": {"@timestamp": {"gte": self.search_after.isoformat() + "Z"}}},
            )

        full_query = {"bool": {}}
        if must:
            full_query["bool"]["must"] = must
        if should:
            full_query["bool"]["should"] = should
            full_query["bool"]["minimum_should_match"] = 1
        if must_not:
            full_query["bool"]["must_not"] = must_not
        if filter:
            full_query["bool"]["filter"] = filter

        return self._search(full_query)

    def search_match(self, terms: dict[str, str]):
        """
        Convenience function for searching for matches using key–values in a dict

        Each key–value pairs will be expanded into individual "must" "match" objects. Example:
        `search_match({"foo": "bar", "baz": "qux"})`
        will generate
        `[{"match": {"foo": "bar"}}, {"match": {"baz": "qux"}}]`
        that will be used as the argument "must" in search().
        """
        return self.search([{"match": {key: value}} for key, value in terms.items()])

    # TODO: implement query_string/simple_query_string (ignoring errors) for searching all fields (Text observable)?

    def search_multi(
        self,
        *,
        fields: list[str],
        value: str,
    ):
        return self.search(
            {
                "multi_match": {
                    "query": value,
                    "fields": fields,
                }
            }
        )

    def search_multi_glob(self, *, fields: list[str], glob: str):
        if any("*" in field for field in fields):
            raise ValueError(
                "Fields in an OpenSearch wildcard query cannot contain globs"
            )

        return self.search(should=[{"wildcard": {field: glob}} for field in fields])

    def search_multi_regex(
        self, *, fields: list[str], regexp: str, case_insensitive: bool = False
    ):
        if any("*" in field for field in fields):
            raise ValueError(
                "Fields in an OpenSearch regexp query cannot contain globs"
            )

        return self.search(
            should=[
                {
                    "regexp": {
                        field: {"value": regexp, "case_insensitive": case_insensitive}
                    }
                }
                for field in fields
            ]
        )

    # TODO: create an API that can chain "wildcard", "match" etc. to build should, must etc.?


# def wildcard(fields: list[str], glob: str):
#    if any("*" in field for field in fields):
#        raise ValueError(
#            "Fields in an OpenSearch wildcard query cannot contain globs"
#        )
#
#    return [{"wildcard": {field: glob}} for field in fields]
