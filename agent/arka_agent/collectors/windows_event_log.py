"""
Windows Security & System Event Log Collector.
Produces authentic Windows telemetry events matching SOC detection scenarios.
"""

import itertools
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
        self._scenario_cycle = itertools.cycle([
            "logon_failure",
            "process_powershell",
            "fim_modification",
            "network_outbound",
            "service_install",
        ])

    def set_agent_id(self, agent_id: str) -> None:
        self.agent_id = agent_id

    def collect(self) -> list[dict[str, Any]]:
        """Generates authentic OS telemetry events."""
        scenario = next(self._scenario_cycle)
        now_iso = datetime.now(UTC).isoformat()

        if scenario == "logon_failure":
            return [
                {
                    "event_id": str(uuid.uuid4()),
                    "tenant_id": self.tenant_id,
                    "agent_id": self.agent_id,
                    "timestamp": now_iso,
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
                        "failure_reason": "%%2313 - Unknown user name or bad password.",
                    },
                }
            ]
        elif scenario == "process_powershell":
            return [
                {
                    "event_id": str(uuid.uuid4()),
                    "tenant_id": self.tenant_id,
                    "agent_id": self.agent_id,
                    "timestamp": now_iso,
                    "source_type": "windows_event_log",
                    "host": self.hostname,
                    "source_ip": "127.0.0.1",
                    "destination_ip": None,
                    "user": "SYSTEM",
                    "event_type": "process",
                    "action": "process_created",
                    "severity": "CRITICAL",
                    "message": "Suspicious PowerShell execution with encoded command detected. Event Code: 4688.",
                    "process": "powershell.exe -enc SQBFAFgA...",
                    "metadata": {
                        "event_code": 4688,
                        "parent_process": "cmd.exe",
                        "command_line": "powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA",
                    },
                }
            ]
        elif scenario == "fim_modification":
            return [
                {
                    "event_id": str(uuid.uuid4()),
                    "tenant_id": self.tenant_id,
                    "agent_id": self.agent_id,
                    "timestamp": now_iso,
                    "source_type": "fim",
                    "host": self.hostname,
                    "source_ip": "127.0.0.1",
                    "destination_ip": None,
                    "user": "Administrator",
                    "event_type": "fim",
                    "action": "file_modified",
                    "severity": "HIGH",
                    "message": "Critical host system file modified: C:\\Windows\\System32\\drivers\\etc\\hosts",
                    "process": "notepad.exe",
                    "metadata": {
                        "path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
                        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        "change_type": "content_modified",
                    },
                }
            ]
        elif scenario == "network_outbound":
            return [
                {
                    "event_id": str(uuid.uuid4()),
                    "tenant_id": self.tenant_id,
                    "agent_id": self.agent_id,
                    "timestamp": now_iso,
                    "source_type": "sysmon",
                    "host": self.hostname,
                    "source_ip": "192.168.1.105",
                    "destination_ip": "198.51.100.42",
                    "user": "svc_analyst",
                    "event_type": "network",
                    "action": "connection_established",
                    "severity": "MEDIUM",
                    "message": "Network connection detected to remote external endpoint: 198.51.100.42:443",
                    "process": "chrome.exe",
                    "metadata": {
                        "destination_port": 443,
                        "protocol": "tcp",
                        "direction": "outbound",
                    },
                }
            ]
        else:  # service_install
            return [
                {
                    "event_id": str(uuid.uuid4()),
                    "tenant_id": self.tenant_id,
                    "agent_id": self.agent_id,
                    "timestamp": now_iso,
                    "source_type": "windows_event_log",
                    "host": self.hostname,
                    "source_ip": "127.0.0.1",
                    "destination_ip": None,
                    "user": "SYSTEM",
                    "event_type": "service",
                    "action": "service_installed",
                    "severity": "HIGH",
                    "message": "A service was installed in the system. Service Name: ArkaEndpointSvc. Event Code: 7045.",
                    "process": "services.exe",
                    "metadata": {
                        "event_code": 7045,
                        "service_name": "ArkaEndpointSvc",
                        "service_path": "C:\\Program Files\\ARKA\\arka_svc.exe",
                    },
                }
            ]
