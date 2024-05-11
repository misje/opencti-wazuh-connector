"""Wazuh connector module"""

from .wazuh import WazuhConnector
from .config import Config

__all__ = ["Config", "WazuhConnector"]
