import logging
from pydantic import AliasPath, AnyHttpUrl, BaseModel, Field
from pydantic_settings import SettingsConfigDict
from urllib.parse import urljoin
from wazuh.stix_helper import STIXList

from .config import Config
from .config_base import ConfigBase
from .stix_helper import entity_value
from .utils import escape_markdown, field_or_empty, md_table

# TODO: create links to alert in all relationships in enrichment
# TODO: check how priorities are calculated. makes sense? Customisable?
# TODO: Improve IR descriptions with why the incidents was created based on
# settings and thresholds (like: vuln. has CVSS score x.x, detection is true
# etc.) Perhaps also for incidents not just IR cases?

log = logging.getLogger(__name__)


class DescriberConfig(ConfigBase):
    """
    Configuration for the Describer module

    See :attr:`~wazuh.config.Config` for documentation of settings (they
    go by the same name and are simply copied).
    """

    model_config = SettingsConfigDict(validate_assignment=True, extra="ignore")

    app_url: AnyHttpUrl
    wazuh_version: Config.WazuhVersion
    opensearch_index: str = Field(validation_alias=AliasPath("opensearch", "index"))


class Describer(BaseModel):
    config: DescriberConfig

    def create_md_link(self, name: str, link: str) -> str:
        """
        Create a Markdown link with the provided link and display name
        """
        return f"[{escape_markdown(name)}]({link})"

    def alert_rule_link(self, rule_id: str) -> str:
        """
        Create a link to Wazuh describing the provided alert rule
        """
        match self.config.wazuh_version:
            case Config.WazuhVersion.v47:
                app_endpoint = "wazuh"
            case Config.WazuhVersion.v48:
                app_endpoint = "threat-hunting"
            case _:
                raise ValueError(
                    f"Cannot create alert rule link because Wazuh version is invalid: {self.config.wazuh_version}"
                )

        return urljoin(
            str(self.config.app_url),
            f"app/{app_endpoint}#/manager/?tab=rules&redirectRule={rule_id}",
        )

    def alert_rule_md_link(self, rule_id: str) -> str:
        """
        Create a Markdown link to Wazuh describing the provided alert rule
        """
        return self.create_md_link(rule_id, self.alert_rule_link(rule_id))

    def alert_context_link(self, alert: dict) -> str:
        """
        Create a link to the alert in Wazuh in OpenSearch's Discover context
        mode
        """
        return urljoin(
            str(self.config.app_url),
            f"app/discover#/context/{self.config.opensearch_index}/{alert['_id']}?_g=(filters:!())&_a=(columns:!(agent.id,agent.name,rule.description,rule.level,rule.id),filters:!())",
        )

    def alert_context_md_link(self, alert: dict) -> str:
        """
        Create a Markdown link to the alert in Wazuh in OpenSearch's Discover
        context mode
        """
        return self.create_md_link(alert["_id"], self.alert_context_link(alert))

    def alert_md_table(
        self, alert: dict, additional_rows: list[tuple[str, str]] | None = None
    ):
        """
        Create a markdown table with key Wazuh alert information

        Any additional rows can be appended to the table using
        :paramref:`additional_rows`.
        """
        s = alert["_source"]
        if additional_rows is None:
            additional_rows = []

        return (
            "|Key|Value|\n"
            "|---|-----|\n"
            f"|Rule ID|{self.alert_rule_md_link(s['rule']['id'])}|\n"
            f"|Rule desc.|{s['rule']['description']}|\n"
            f"|Rule level|{s['rule']['level']}|\n"
            f"|Alert ID|{self.alert_context_md_link(alert)}|\n"
        ) + "".join(
            f"|{escape_markdown(key)}|{escape_markdown(value)}|\n"
            for key, value in additional_rows
        )

    def enrichment_relation_desc(
        self,
        *,
        entity_type: str,
        name: str | None = None,
        field: str | None = None,
        alert: dict,
    ) -> str:
        if name is None and field is None:
            found_str = "found "
        elif field is None:
            found_str = f"{name} found "
        elif name is None:
            found_str = f"found in {field} "
        else:
            found_str = f"{name} found in {field} "

        return (
            f"{entity_type} {found_str}in alert (ID "
            f"{self.alert_context_md_link(alert)}, rule ID "
            f"{self.alert_rule_md_link(alert['_source']['rule']['id'])}): "
            f"{alert['_source']['rule']['description']}"
        )

    def ir_case_desc(
        self, *, entity: dict, indicators: list[dict], result: dict, bundle: STIXList
    ) -> str:
        # hits_returned = len(result["hits"]["hits"])
        # total_hits = result["hits"]["total"]["value"]
        return md_table(
            [
                ("Entity type", entity["entity_type"]),
                ("Entity value", entity_value(entity)),
                ("Entity author", field_or_empty(entity, "createdBy.name", str)),
            ]
            + [
                ("Indicator based on", observable["observable_value"])
                for indicator in indicators
                for observable in field_or_empty(indicator, "observables", list)
            ],
            header=("Key", "Value"),
        )
