import urllib3
import json
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

    def __init__(
        self,
        *,
        helper: OpenCTIConnectorHelper,
        url: str,
        username: str,
        password: str,
        limit: int,
        index: str,
        search_after: datetime | None,
        include_match: list[dict] | None,
        exclude_match: list[dict] | None,
    ) -> None:
        self.url = url
        self.username = username
        self.password = password
        self.index = index
        self.limit = limit
        self.helper = helper
        self.search_after = search_after
        self.include_match = include_match
        self.exclude_match = exclude_match

        self.helper.connector_logger.info(f"[Wazuh] URL: {self.url}")

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

            try:
                # TODO: reponse now guaranteed to be 200?
                self.helper.connector_logger.debug(
                    f"[Wazuh] Query response status: {response.status_code}"
                )
                # self.helper.connector_logger.debug(
                #    f"[Wazuh] Query response: {response.json()}"
                # )
                return response.json()
            except json.JSONDecodeError as e:
                self.helper.connector_logger.error(
                    f"[Wazuh] Query: Failed to parse response: {response.text}: {e}"
                )
                self.helper.metric.inc("client_error_count")
                return None

        except requests.exceptions.HTTPError as e:
            self.helper.connector_logger.error(f"[Wazuh] Query: HTTP error: {e}")
            self.helper.metric.inc("client_error_count")
        except requests.exceptions.ConnectionError as e:
            self.helper.connector_logger.error(f"[Wazuh] Query: Connection error: {e}")
            self.helper.metric.inc("client_error_count")
        except requests.exceptions.Timeout as e:
            self.helper.connector_logger.error(f"[Wazuh] Query: Timed out: {e}")
            self.helper.metric.inc("client_error_count")
        except requests.exceptions.URLRequired:
            self.helper.connector_logger.error(
                "f[Wazuh] Query: URL not set or invalid: {self.url}"
            )
            self.helper.metric.inc("client_error_count")
        except Exception as e:
            self.helper.connector_logger.error(f"[Wazuh] Query: Unknown error: {e}")
            self.helper.metric.inc("client_error_count")

    def _search(self, query: dict):
        query = {
            "query": query,
            "size": self.limit,
            "sort": [{"timestamp": {"order": "desc"}}],
        }
        self.helper.connector_logger.debug(f'Sending query "{query}"')

        r = self._query(f"{self.index}/_search", query=query)
        if not r:
            return None
        try:
            if r["timed_out"]:
                self.helper.connector_logger.warning(
                    "[Wazuh] OpenSearch: Query timed out"
                )
                self.helper.connector_logger.debug(
                    "[Wazuh] OpenSearh: Searched {}/{} shards, {} skipped, {} failed".format(
                        r["_shards"]["successful"],
                        r["_shards"]["total"],
                        r["_shards"]["skipped"],
                        r["_shards"]["failed"],
                    )
                )
            # TODO: print if shards has failed?
            # TODO: pagination?
            if r["hits"]["total"]["value"] > self.limit:
                self.helper.connector_logger.warning(
                    "[Wazuh] Processing only {} of {} hits (hint: increase 'max_hits')".format(
                        self.limit, r["hits"]["total"]["value"]
                    )
                )

            return r
            # return [hit for hit in r["hits"]["hits"]]

        # TODO: How to propagate errors to gui. Just exceptions? Look up connector doc.
        except (IndexError, KeyError):
            self.helper.connector_logger.error(
                "[Wazuh]: Failed to parse result: Unexpected JSON structure"
            )
            self.helper.metric.inc("client_error_count")

    def search(
        self,
        must: dict | list[dict] | None = None,
        must_not: dict | list[dict] | None = None,
        should: dict | list[dict] | None = None,
    ):
        if not must and not must_not and not should:
            raise ValueError("One of must, must_not and should must be non-empty")

        must = must if isinstance(must, list) else [must] if must else []
        should = should if isinstance(should, list) else [should] if should else []
        must_not = (
            must_not if isinstance(must_not, list) else [must_not] if must_not else []
        )

        must = must + (self.include_match or [])
        must_not = must_not + (self.exclude_match or [])

        full_query = {"bool": {}}
        if must:
            full_query["bool"]["must"] = must
        if should:
            full_query["bool"]["should"] = should
            full_query["bool"]["minimum_should_match"] = 1
        if must_not:
            full_query["bool"]["must_not"] = must_not
        if self.search_after:
            full_query["bool"]["filter"] = [
                {"range": {"@timestamp": {"gte": self.search_after.isoformat() + "Z"}}}
            ]

        return self._search(full_query)

    def search_match(self, terms: dict):
        return self.search([{"match": {key: value}} for key, value in terms.items()])

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

    # TODO: raise if any fields contains globs(?):
    def search_multi_glob(self, *, fields: list[str], value: str):
        return self.search(should=[{"wildcard": {field: value}} for field in fields])
