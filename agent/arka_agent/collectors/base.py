"""
Base Abstract Collector Interface.
"""

from abc import ABC, abstractmethod
from typing import Any


class BaseCollector(ABC):
    """Abstract Base Class for OS Telemetry Collectors."""

    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled

    @abstractmethod
    def collect(self) -> list[dict[str, Any]]:
        """Harvests new security events from system logs or APIs."""
