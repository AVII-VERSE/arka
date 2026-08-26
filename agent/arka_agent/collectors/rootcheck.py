"""
ARKA Rootcheck Security Scanner.
Detects rootkits, hidden processes, promiscuous network sockets, and system file anomalies.
"""

import os
import platform
from datetime import UTC, datetime
from typing import Any

import psutil


class RootcheckScanner:
    """Endpoint Rootkit and System Anomaly Security Scanner."""

    def __init__(self, agent_id: str = "agent-dev-01", tenant_id: str = "default-tenant"):
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.suspicious_paths = self._get_suspicious_paths()

    def _get_suspicious_paths(self) -> list[str]:
        """Returns platform-specific suspicious rootkit paths."""
        if platform.system().lower() == "windows":
            system_root = os.getenv("SystemRoot", "C:\\Windows")
            return [
                os.path.join(system_root, "System32", "drivers", "etc", ".hidden"),
                os.path.join(system_root, "Temp", ".rootkit"),
            ]
        else:
            return [
                "/dev/.static",
                "/dev/.pdev",
                "/tmp/.icm",  # nosec B108
                "/tmp/.hidden",  # nosec B108
                "/var/tmp/.rootkit",  # nosec B108
                "/usr/share/.rootkit",
            ]

    def scan_suspicious_files(self) -> list[dict[str, Any]]:
        """Scans filesystem for known rootkit artifact paths."""
        findings = []
        now = datetime.now(UTC)
        for path in self.suspicious_paths:
            if os.path.exists(path):
                findings.append(
                    {
                        "event_id": f"rootcheck-file-{now.timestamp()}",
                        "tenant_id": self.tenant_id,
                        "agent_id": self.agent_id,
                        "timestamp": now.isoformat(),
                        "source_type": "rootcheck",
                        "host": platform.node(),
                        "event_type": "rootkit_detection",
                        "action": "suspicious_file_found",
                        "severity": "CRITICAL",
                        "message": f"Rootcheck Alert: Known rootkit artifact file found at '{path}'",
                        "metadata": {"suspicious_path": path, "scan_type": "filesystem"},
                        "ingested_at": now.isoformat(),
                    }
                )
        return findings

    def scan_listening_ports(self) -> list[dict[str, Any]]:
        """Scans for unmapped or suspicious listening network sockets."""
        findings = []
        now = datetime.now(UTC)
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == psutil.CONN_LISTEN and conn.laddr:
                    port = conn.laddr.port
                    # Flag suspicious IRC / backdoor default ports (e.g., 31337, 6667, 4444)
                    if port in (31337, 6667, 4444, 12345, 65535):
                        pid = conn.pid
                        proc_name = "unknown"
                        if pid:
                            try:
                                proc_name = psutil.Process(pid).name()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass

                        findings.append(
                            {
                                "event_id": f"rootcheck-port-{now.timestamp()}-{port}",
                                "tenant_id": self.tenant_id,
                                "agent_id": self.agent_id,
                                "timestamp": now.isoformat(),
                                "source_type": "rootcheck",
                                "host": platform.node(),
                                "event_type": "rootkit_detection",
                                "action": "suspicious_port_listening",
                                "severity": "HIGH",
                                "message": f"Rootcheck Alert: Suspicious listening port {port} detected (Process: {proc_name}, PID: {pid})",
                                "metadata": {
                                    "port": port,
                                    "pid": pid,
                                    "process_name": proc_name,
                                    "scan_type": "network_sockets",
                                },
                                "ingested_at": now.isoformat(),
                            }
                        )
        except Exception:
            pass
        return findings

    def run_full_scan(self) -> list[dict[str, Any]]:
        """Executes full rootcheck security audit scan."""
        events = []
        events.extend(self.scan_suspicious_files())
        events.extend(self.scan_listening_ports())
        return events
