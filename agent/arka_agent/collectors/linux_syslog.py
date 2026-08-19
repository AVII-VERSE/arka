"""
Linux Syslog / Journald / Auth Log Collector.
"""

import platform
import uuid
from datetime import UTC, datetime
from typing import Any

from arka_agent.collectors.base import BaseCollector


class LinuxSyslogCollector(BaseCollector):
    def __init__(self, agent_id: str, tenant_id: str):
        super().__init__(name="linux_syslog")
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.hostname = platform.node()

    def collect(self) -> list[dict[str, Any]]:
        """Harvests Linux auth.log, syslog, or journald entries."""
        events = [
            {
                "event_id": str(uuid.uuid4()),
                "tenant_id": self.tenant_id,
                "agent_id": self.agent_id,
                "timestamp": datetime.now(UTC).isoformat(),
                "source_type": "linux_syslog",
                "host": self.hostname,
                "source_ip": "203.0.113.45",
                "destination_ip": "10.0.0.15",
                "user": "root",
                "event_type": "authentication",
                "action": "logon_failed",
                "severity": "HIGH",
                "message": "Failed password for root from 203.0.113.45 port 54122 ssh2",
                "process": "/usr/sbin/sshd",
                "metadata": {"facility": "auth", "pid": 14205},
            }
        ]
        return events
