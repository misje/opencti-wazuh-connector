import urllib3
import requests
import logging
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from urllib.parse import urljoin
from pydantic import ValidationError
from datetime import datetime, timedelta
from typing import Sequence

from wazuh.opensearch_dsl import (
    Bool,
    Match,
    MultiMatch,
    Range,
    Query,
    QueryType,
    Regexp,
    Wildcard,
)
from wazuh.utils import remove_empties
from .opensearch_config import OpenSearchConfig

log = logging.getLogger(__name__)


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

    class SearchError(Exception):
        def __init__(self, message):
            super().__init__(message)

    def __init__(self, *, config: OpenSearchConfig) -> None:
        self.config = config

        adapter = HTTPAdapter(
            max_retries=Retry(
                total=3,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "OPTIONS"],
            )
        )
        http = self.http = requests.Session()
        http.auth = (self.config.username, self.config.password)
        http.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        http.mount(str(self.config.url), adapter)
        # TODO:: allow import of cert
        http.verify = self.config.verify_tls

        # TODO: remove:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _query(self, endpoint, query):
        try:
            response = self.http.get(
                urljoin(str(self.config.url), endpoint),
                json=query,
                timeout=self.config.timeout.total_seconds(),
            )
            response.raise_for_status()

            return response.json()

        except requests.JSONDecodeError as e:
            raise self.ParseError(f"Failed to parse JSON response: {e}") from e
        except requests.exceptions.RequestException as e:
            raise self.ConnectionError(
                f"Failed to connect to {str(self.config.url)}: {e}"
            ) from e

    def _search(self, query: Query):
        conf = self.config
        if query.size is None:
            query.size = conf.limit
        if query.sort is None:
            query.sort = conf.order_by

        # Removing nones and unsets doesn't work for nested models:
        serialised = remove_empties(
            query.model_dump(exclude_none=True, exclude_unset=True)
        )
        log.debug(f'Sending query "{serialised}"')

        r = self._query(
            f"{conf.index}/_search",
            query=serialised,
        )
        if not r:
            return None
        try:
            if r["timed_out"]:
                raise self.SearchError("Query timed out")

            log.debug(
                "OpenSearch: Searched {}/{} shards, {} skipped, {} failed".format(
                    r["_shards"]["successful"],
                    r["_shards"]["total"],
                    r["_shards"]["skipped"],
                    r["_shards"]["failed"],
                )
            )
            if r["hits"]["total"]["value"] > conf.limit:
                log.warning(
                    "Processing only {} of {} hits (hint: increase 'opensearch.limit')".format(
                        conf.limit, r["hits"]["total"]["value"]
                    )
                )

            return r

        except (IndexError, KeyError) as e:
            raise self.ParseError(
                "Failed to parse result: Unexpected JSON structure"
            ) from e

    def search(
        self,
        must: Sequence[QueryType] | None = None,
        *,
        must_not: Sequence[QueryType] | None = None,
        should: Sequence[QueryType] | None = None,
        filter: Sequence[QueryType] | None = None,
    ):
        conf = self.config
        if filter is None:
            filter = []
            if isinstance(conf.search_after, datetime):
                filter += [
                    Range(field="@timestamp", gte=conf.search_after.isoformat() + "Z")
                ]
            elif isinstance(conf.search_after, timedelta):
                timestamp = datetime.now() - conf.search_after
                filter += [Range(field="@timestamp", gte=timestamp.isoformat() + "Z")]

            if conf.include_match or conf.exclude_match:
                filter += [Bool(must=conf.include_match, must_not=conf.exclude_match)]
        try:
            return self._search(
                Query(
                    query=Bool(
                        must=must or [],
                        must_not=must_not or [],
                        should=should or [],
                        filter=filter or conf.filter,
                    )
                )
            )
        except ValidationError as e:
            raise self.QueryError("Failed to create query") from e

    def search_match(self, terms: dict[str, str]):
        """
        Convenience function for searching for matches using key–values in a dict

        Each key–value pairs will be expanded into individual "must" "match" objects. Example:
        `search_match({"foo": "bar", "baz": "qux"})`
        will generate
        `[{"match": {"foo": "bar"}}, {"match": {"baz": "qux"}}]`
        that will be used as the argument "must" in search().
        """
        return self.search(
            [Match(field=key, query=value) for key, value in terms.items()]
        )

    def search_multi(
        self,
        *,
        fields: list[str],
        value: str,
    ):
        return self.search([MultiMatch(fields=fields, query=value)])

    def search_multi_glob(self, *, fields: list[str], glob: str):
        return self.search(
            should=[Wildcard(field=field, query=glob) for field in fields]
        )

    def search_multi_regex(
        self, *, fields: list[str], regexp: str, case_insensitive: bool = False
    ):
        return self.search(
            should=[
                Regexp(field=field, query=regexp, case_insensitive=case_insensitive)
                for field in fields
            ]
        )
