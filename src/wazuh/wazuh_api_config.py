from pydantic import AnyHttpUrl, AnyUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from .utils import verify_url


class WazuhAPIConfig(BaseSettings):
    """
    FIXME
    """

    model_config = SettingsConfigDict(env_prefix="WAZUH_API_", validate_assignment=True)

    enabled: bool = False
    # Compute from opensearch?
    url: AnyHttpUrl | str | None = None
    username: str | None = None
    password: str | None = None
    verify_tls: bool = True

    @field_validator("url", mode="before")
    @classmethod
    def parse_http_url(cls, url: str | AnyHttpUrl | None) -> AnyHttpUrl | None:
        """
        Convert a URL string to a AnyHttpUrl
        """
        if url is None:
            return None
        elif isinstance(url, AnyUrl):
            return url
        else:
            return AnyHttpUrl(url)

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
