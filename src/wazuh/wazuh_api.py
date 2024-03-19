from stix2.parsing import ParseError
import urllib3
import requests
import concurrent.futures
from datetime import datetime, timedelta
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth
from urllib3.util import Retry
from urllib.parse import urljoin
from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    ValidationError,
    TypeAdapter,
)
from pydantic.networks import IPvAnyAddress
from typing import Literal
from os import makedirs
from os.path import dirname


class WAPIResult(BaseModel):
    scan_time: datetime = Field(validation_alias=AliasChoices("scan", "scan_time"))

    @field_validator("scan_time", mode="before")
    @classmethod
    def extract_scan_time(cls, scan: dict | str):
        return scan["time"] if isinstance(scan, dict) else scan


class Package(WAPIResult):
    name: str
    vendor: str
    version: str


class Process(WAPIResult):
    name: str
    cmd: str | None = None
    # cmd (optional):
    # - Linux: full path, no args.
    # - macOS:
    # - Windows: full path, no args.
    start_time: datetime
    argvs: str | None = None  # Linux only
    pid: int = Field(ge=0)  # tie to parent_ref, child_refs
    ppid: int = Field(ge=0)  # tie to parent_ref, child_refs

    # @field_validator('name', mode='after'): # ensure name isn't a path


# create Network-Traffic
class Connection(WAPIResult):
    protocol: Literal["tcp", "tcp6", "udp", "udp6"]
    local_ip: IPvAnyAddress = Field(validation_alias=AliasChoices("local", "local_ip"))
    local_port: int = Field(validation_alias=AliasChoices("local"), ge=0)
    remote_ip: IPvAnyAddress = Field(
        validation_alias=AliasChoices("remote", "remote_ip")
    )
    remote_port: int = Field(
        validation_alias=AliasChoices("remote", "remote_port"), ge=0
    )
    process_pid: int = Field(
        validation_alias=AliasChoices("pid", "process_pid"), ge=0
    )  # reference Process.pid)
    process_name: str = Field(validation_alias=AliasChoices("process", "process_name"))

    @field_validator("local_ip", "remote_ip", mode="before")
    def parse_ip(cls, address: dict | str):
        return address["ip"] if isinstance(address, dict) else address

    @field_validator("local_port", "remote_port", mode="before")
    def parse_port(cls, address: dict | str):
        return address["port"] if isinstance(address, dict) else address


class OS(BaseModel):
    name: str
    version: str


class Agent(BaseModel):
    scan_time: datetime = datetime.now()
    id: str = Field(pattern=r"^\d{3,}$", frozen=True)
    name: str
    status: Literal[
        "active", "pending", "never_connected", "disconnected"
    ] | None = None
    disconnected_time: datetime | None = None
    os: OS | None = None
    version: str | None = None
    ip: IPvAnyAddress | None = None
    packages: list[Package] = []
    processes: dict[int, Process] = {}
    connections: list[Connection] = []

    model_config = ConfigDict(validate_assignment=True)

    @field_validator("ip", mode="before")
    @classmethod
    def ignore_any(cls, ip: str):
        return None if ip == "any" else ip


class CacheValidity(BaseModel):
    duration: timedelta
    scan_time: datetime | None = None

    def is_valid(self):
        return self.scan_time and datetime.now() - self.scan_time <= self.duration


class State(BaseModel):
    agents: dict[str, Agent] = {}
    agents_cache_validity: CacheValidity = CacheValidity(duration=timedelta(days=1))
    packages_cache_validity: CacheValidity = CacheValidity(duration=timedelta(days=1))
    processes_cache_validity: CacheValidity = CacheValidity(
        duration=timedelta(minutes=5)
    )
    connections_cache_validity: CacheValidity = CacheValidity(
        duration=timedelta(minutes=5)
    )


class WazuhAPIClient:
    # TODO: reuse through inheritance along with OpenSearchClient:
    class ConnectionError(Exception):
        def __init__(self, message):
            super().__init__(message)

    class ParseError(Exception):
        def __init__(self, message):
            super().__init__(message)

    def __init__(
        self,
        *,
        helper: OpenCTIConnectorHelper,
        url: str,
        username: str,
        password: str,
        cache_filename: str,
    ):
        self.helper = helper
        self.url = url
        self.username = username
        self.password = password
        self.jwt = None
        self.jwt_timestamp = None
        self.cache_filename = cache_filename
        self.state = State()

        makedirs(dirname(self.cache_filename), exist_ok=True)

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _query(self, endpoint, params, *, method="GET", auth=None, headers: dict = {}):
        adapter = HTTPAdapter(
            max_retries=Retry(
                total=3,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
            )
        )
        http = requests.Session()
        http.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **headers,
        }
        http.mount(self.url, adapter)
        # TODO:: allow import of cert
        http.verify = False

        try:
            method_func = {"GET": http.get, "POST": http.post}[method]
            response = method_func(
                urljoin(self.url, endpoint),
                params=params,
                auth=auth,
            )
            response.raise_for_status()

            return response.json()

        except KeyError:
            raise ValueError(f"Unknown method: {method}")
        except requests.JSONDecodeError as e:
            raise self.ParseError(f"Failed to parse JSON response: {e}") from e
        except requests.exceptions.RequestException as e:
            raise self.ConnectionError(f"Failed to connect to {self.url}: {e}") from e

    def login(self):
        self.helper.connector_logger.debug(
            f"Logging into Wazuh API at {self.url} as user {self.username}"
        )
        response = self._query(
            "security/user/authenticate",
            {},
            method="POST",
            auth=HTTPBasicAuth(self.username, self.password),
        )
        if "data" not in response and "token" not in response["data"]:
            raise ConnectionError("Failed to authenticate")

        self.jwt = response["data"]["token"]
        self.jwt_timestamp = datetime.now()
        self.helper.connector_logger.info(
            f"Successfully logged into Wazuh API at {self.url} as user {self.username}"
        )

    def query(self, endpoint, params={}):
        if (
            not self.jwt_timestamp
            or (datetime.now() - self.jwt_timestamp).total_seconds() >= 900
        ):
            self.login()

        return self._query(
            endpoint, params, headers={"Authorization": f"Bearer {self.jwt}"}
        )

    def query_agents(self):
        self.helper.log_info(
            f"{self.state.agents_cache_validity.scan_time}, {self.state.agents_cache_validity.duration}"
        )
        if self.state.agents_cache_validity.is_valid():
            self.helper.connector_logger.debug("Agents cache up to date, not querying")
            return

        self.helper.connector_logger.debug("Querying Wazuh agents")
        response = self.query("agents")
        try:
            self.state.agents = {
                agent["id"]: Agent(**agent)
                for agent in response["data"]["affected_items"]
            }
        except ValidationError as e:
            raise ParseError(
                f"Failed to parse response from Wazuh agents query: {e}"
            ) from e

        self.state.agents_cache_validity.scan_time = datetime.now()
        self.helper.connector_logger.info(
            f"Wazuh agent list retrieved ({len(self.state.agents)} agents)"
        )

    def query_agent_packages(self, agent_id: str):
        self.helper.connector_logger.debug(
            f"Querying packages for Wazuh agent {agent_id}"
        )
        response = self.query(
            f"syscollector/{agent_id}/packages",
        )  # {"limit": 10_000})
        try:
            self.state.agents[agent_id].packages = TypeAdapter(
                list[Package]
            ).validate_python(response["data"]["affected_items"])
        except ValidationError as e:
            raise ParseError(
                f"Failed to parse response from Wazuh packages query: {e}"
            ) from e

        self.helper.connector_logger.info(
            f"{len(self.state.agents[agent_id].packages)} packages retrieved for agent {agent_id}"
        )

    def query_packages(self):
        if self.state.packages_cache_validity.is_valid():
            self.helper.connector_logger.debug(
                "Agent packages cache up to date, not querying"
            )
            return

        self.query_agents()

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(
                    self.query_agent_packages,
                    agent.id,
                )
                for agent in list(self.state.agents.values())
            ]
            [future for future in concurrent.futures.as_completed(futures)]

        self.state.packages_cache_validity.scan_time = datetime.now()

    def query_agent_connections(self, agent_id: str):
        self.helper.connector_logger.debug(
            f"Querying connections for Wazuh agent {agent_id}"
        )
        response = self.query(f"syscollector/{agent_id}/ports")
        try:
            self.state.agents[agent_id].connections = TypeAdapter(
                list[Connection]
            ).validate_python(response["data"]["affected_items"])
        except ValidationError as e:
            raise ParseError(
                f"Failed to parse response from Wazuh connections query: {e}"
            ) from e

        self.helper.connector_logger.info(
            f"{len(self.state.agents[agent_id].connections)} connections retrieved for agent {agent_id}"
        )

    def query_connections(self):
        if self.state.connections_cache_validity.is_valid():
            self.helper.connector_logger.debug(
                "Agent connections cache up to date, not querying"
            )
            return

        self.query_agents()

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [
                executor.submit(
                    self.query_agent_connections,
                    agent.id,
                )
                for agent in list(self.state.agents.values())
            ]
            [future for future in concurrent.futures.as_completed(futures)]

        self.state.connections_cache_validity.scan_time = datetime.now()

    def query_agent_processes(self, agent_id: str):
        self.helper.connector_logger.debug(
            f"Querying processes for Wazuh agent {agent_id}"
        )
        response = self.query(f"syscollector/{agent_id}/processes")
        try:
            self.state.agents[agent_id].processes = {
                process["pid"]: Process(**process)
                for process in response["data"]["affected_items"]
            }
        except ValidationError as e:
            raise ParseError(
                f"Failed to parse response from Wazuh processes query: {e}"
            ) from e

        self.helper.connector_logger.info(
            f"{len(self.state.agents[agent_id].connections)} processes retrieved for agent {agent_id}"
        )

    def query_processes(self):
        if self.state.processes_cache_validity.is_valid():
            self.helper.connector_logger.debug(
                "Agent processes cache up to date, not querying"
            )
            return

        self.query_agents()

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(
                    self.query_agent_processes,
                    agent.id,
                )
                for agent in list(self.state.agents.values())
            ]
            [future for future in concurrent.futures.as_completed(futures)]

        self.state.processes_cache_validity.scan_time = datetime.now()

    # def refresh(self):
    #    self.query_agents()

    #    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    #        queries = [
    #            self.query_agent_packages,
    #            self.query_agent_connections,
    #            self.query_agent_processes,
    #        ]
    #        futures = [
    #            executor.submit(
    #                lambda agent_id, query: query(agent_id),
    #                agent.id,
    #                query,
    #            )
    #            for agent in list(self.state.agents.values())
    #            for query in queries
    #        ]

    #        [future for future in concurrent.futures.as_completed(futures)]

    def save_cache(self):
        self.helper.connector_logger.info(f"Saving cache to {self.cache_filename}")
        try:
            with open(self.cache_filename, "w", encoding="utf-8") as cache:
                cache.write(self.state.model_dump_json())
        except (OSError, IOError) as e:
            self.helper.connector_logger.warning(f"Failed to save cache: {e}")

    def load_cache(self):
        self.helper.connector_logger.info(f"Loading cache from {self.cache_filename}")
        try:
            with open(self.cache_filename, "r", encoding="utf-8") as cache:
                self.state.model_validate_json(cache.read())
        except (OSError, IOError, ValidationError) as e:
            self.helper.connector_logger.warning(f"Failed to load cache: {e}")

    def find_package(
        self, name: str, version: str | None = None
    ) -> list[tuple[Agent, Package]]:
        return [
            (agent, package)
            for agent in self.state.agents.values()
            for package in agent.packages
            if package.name == name and (version is None or package.version == version)
        ]
