from pydantic import AnyHttpUrl
from pydantic_settings import SettingsConfigDict
from .config_base import ConfigBase


class OpenCTIConfig(ConfigBase):
    """
    Helper class to parse the most important OpenCTI settings (from file)

    This class is not complete, and does not reference all possible
    configuration options. These are still parsed by opencti_connector_helper.py
    as environment vairables.
    """

    model_config = SettingsConfigDict(
        env_prefix="OPENCTI_",
        validate_assignment=True,
        extra="allow",
    )

    url: AnyHttpUrl
    """
    OpenCTI URL
    """
    token: str
    """
    Token used for authenticating the connector as a user in OpenCTI

    See :ref:`creating an OpenCTI user <create-opencti-user>` for details.
    """
    ssl_verify: bool = False
    """
    Whether to verify OpenCTI's TLS certificate

    .. warning::

        Disabling the certificate check is highly discouraged. Using a signed
        certificate is a much preferred solution.
    """
