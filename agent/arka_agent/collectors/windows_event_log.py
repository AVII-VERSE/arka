"""
Windows Security & System Event Log Collector.
"""

import platform
import uuid
from datetime import UTC, datetime
from typing import Any

from arka_agent.collectors.base import BaseCollector


class WindowsEventLogCollector(BaseCollector):
    def __init__(self, agent_id: str, tenant_id: str):
        super().__init__(name="windows_event_log")
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.hostname = platform.node()

    def collect(self) -> list[dict[str, Any]]:
        """Simulates or fetches native Windows Security & System logs."""
        # Clean normalized telemetry schema (No password / sensitive key content)
        events = [
            {
                "event_id": str(uuid.uuid4()),
                "tenant_id": self.tenant_id,
                "agent_id": self.agent_id,
                "timestamp": datetime.now(UTC).isoformat(),
                "source_type": "windows_event_log",
                "host": self.hostname,
                "source_ip": "192.168.1.105",
                "destination_ip": "192.168.1.10",
                "user": "Administrator",
                "event_type": "authentication",
                "action": "logon_failed",
                "severity": "HIGH",
                "message": "An account failed to log on. Logon Type: 3. Event Code: 4625.",
                "process": "C:\\Windows\\System32\\lsass.exe",
                "metadata": {
                    "event_code": 4625,
                    "logon_type": 3,
                    "workstation_name": self.hostname,
                },
            }
        ]
        return events
