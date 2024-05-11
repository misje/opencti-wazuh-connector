from pydantic import AnyHttpUrl
from pydantic_settings import SettingsConfigDict
from .config_base import ConfigBase


class OpenCTIConfig(ConfigBase):
    """
    Connector OpenCTI settings

    These settings are the most important settings used by the connector. There
    are other settings supported by the connector API, but they are not listed
    here, nor is there any official documentation for them.
    """

    model_config = SettingsConfigDict(
        env_prefix="OPENCTI_",
        validate_assignment=True,
        extra="allow",
    )

    url: AnyHttpUrl
    """
    OpenCTI URL

    This is the URL to the OpenCTI server. Connectors are typically run in the
    same docker-compose file as the server. This lets you refer to this URL
    with the variable **${OPENCTI_BASE_URL}**, typically defined in an
    :ref:`.env file <opencti-env>`.
    """
    token: str
    """
    Token used for authenticating the connector as a user in OpenCTI

    This token is used for the connector to access OpenCTI's API. See :ref:`create
    OpenCTI user <create-opencti-user>` for how to create a token. Please refrain
    from using an admin token (like ${OPENCTI_ADMIN_TOKEN}, for reasons described
    in the aforementioned chapter.
    """
    ssl_verify: bool = False
    """
    Whether to verify OpenCTI's TLS certificate

    .. warning::

        If the connector and the OpenCTI server is not running in
        docker-compose, where the connector can directly access the server in a
        closed network, do not disable verification. Use a proper certificate
        in such cases.
    """
