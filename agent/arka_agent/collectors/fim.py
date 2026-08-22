"""
ARKA Endpoint File Integrity Monitoring (FIM) Harvester.
Monitors critical system configuration files for unauthorized modification, creation, or deletion.
"""

import hashlib
import os
import platform
from datetime import UTC, datetime
from typing import Any


class FileIntegrityMonitor:
    """Configurable File Integrity Monitor (FIM) for security-sensitive paths."""

    def __init__(
        self,
        agent_id: str = "agent-dev-01",
        tenant_id: str = "default-tenant",
        monitored_paths: list[str] | None = None,
    ):
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.monitored_paths = monitored_paths or self._get_default_paths()
        self._file_hashes: dict[str, str] = {}
        self._initialize_baseline()

    def _get_default_paths(self) -> list[str]:
        """Returns platform-specific default security configuration paths."""
        if platform.system().lower() == "windows":
            system_root = os.getenv("SystemRoot", "C:\\Windows")
            return [
                os.path.join(system_root, "System32", "drivers", "etc", "hosts"),
                os.path.join(system_root, "System32", "drivers", "etc", "services"),
            ]
        else:
            return [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/sudoers",
                "/etc/ssh/sshd_config",
            ]

    def compute_sha256(self, filepath: str) -> str | None:
        """Computes SHA-256 checksum for a target file."""
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            return None
        try:
            hasher = hashlib.sha256()
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None

    def _initialize_baseline(self) -> None:
        """Calculates initial SHA-256 hash baseline for monitored paths."""
        for path in self.monitored_paths:
            h = self.compute_sha256(path)
            if h:
                self._file_hashes[path] = h

    def check_changes(self) -> list[dict[str, Any]]:
        """Scans monitored paths and emits security events on file creation, modification, or deletion."""
        events: list[dict[str, Any]] = []
        now = datetime.now(UTC)

        for path in self.monitored_paths:
            current_hash = self.compute_sha256(path)
            previous_hash = self._file_hashes.get(path)

            if current_hash is None and previous_hash is not None:
                # File Deleted
                del self._file_hashes[path]
                events.append(
                    {
                        "event_id": f"fim-del-{now.timestamp()}",
                        "tenant_id": self.tenant_id,
                        "agent_id": self.agent_id,
                        "timestamp": now.isoformat(),
                        "source_type": "fim",
                        "host": platform.node(),
                        "event_type": "file_integrity",
                        "action": "file_deleted",
                        "severity": "HIGH",
                        "message": f"FIM Alert: Monitored file '{path}' was deleted.",
                        "metadata": {"file_path": path, "previous_sha256": previous_hash},
                        "ingested_at": now.isoformat(),
                    }
                )
            elif current_hash is not None and previous_hash is None:
                # File Created
                self._file_hashes[path] = current_hash
                events.append(
                    {
                        "event_id": f"fim-cre-{now.timestamp()}",
                        "tenant_id": self.tenant_id,
                        "agent_id": self.agent_id,
                        "timestamp": now.isoformat(),
                        "source_type": "fim",
                        "host": platform.node(),
                        "event_type": "file_integrity",
                        "action": "file_created",
                        "severity": "MEDIUM",
                        "message": f"FIM Alert: Security configuration file '{path}' was created.",
                        "metadata": {"file_path": path, "current_sha256": current_hash},
                        "ingested_at": now.isoformat(),
                    }
                )
            elif current_hash is not None and previous_hash is not None and current_hash != previous_hash:
                # File Modified
                self._file_hashes[path] = current_hash
                events.append(
                    {
                        "event_id": f"fim-mod-{now.timestamp()}",
                        "tenant_id": self.tenant_id,
                        "agent_id": self.agent_id,
                        "timestamp": now.isoformat(),
                        "source_type": "fim",
                        "host": platform.node(),
                        "event_type": "file_integrity",
                        "action": "file_modified",
                        "severity": "HIGH",
                        "message": f"FIM Alert: Hash change detected for security file '{path}'.",
                        "metadata": {
                            "file_path": path,
                            "previous_sha256": previous_hash,
                            "current_sha256": current_hash,
                        },
                        "ingested_at": now.isoformat(),
                    }
                )

        return events
