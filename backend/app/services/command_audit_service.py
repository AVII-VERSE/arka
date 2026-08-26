"""
ARKA Command Execution & Syscall Audit Analytics Engine.
Detects reverse shells, credential harvesting, privilege escalation, and MITRE ATT&CK command patterns.
"""

from typing import Any

from arka_agent.collectors.command_auditor import CommandAuditor

_SUSPICIOUS_PATTERNS: list[dict[str, Any]] = [
    {
        "pattern": "/etc/shadow",
        "category": "CREDENTIAL_HARVESTING",
        "severity": "HIGH",
        "mitre_technique": "T1003.008",
        "description": "Attempted read of shadow password hash file.",
    },
    {
        "pattern": "nc -e",
        "category": "REVERSE_SHELL",
        "severity": "CRITICAL",
        "mitre_technique": "T1059.004",
        "description": "Netcat interactive reverse shell execution.",
    },
    {
        "pattern": "powershell -enc",
        "category": "COMMAND_OBFUSCATION",
        "severity": "HIGH",
        "mitre_technique": "T1027",
        "description": "Base64 encoded PowerShell payload execution.",
    },
    {
        "pattern": "chmod 777",
        "category": "PERMISSION_WEAKENING",
        "severity": "MEDIUM",
        "mitre_technique": "T1222.002",
        "description": "Permissive file permissions assignment.",
    },
]

_AUDIT_LOG_STORE: list[dict[str, Any]] = []


class CommandAuditService:
    """Analyzes process command execution telemetry for threat indicators."""

    @staticmethod
    def analyze_command_events(
        agent_id: str, tenant_id: str, events: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Analyzes command line executions for suspicious indicators."""
        analyzed_events = []
        suspicious_count = 0
        privilege_esc_count = 0

        for evt in events:
            cmd = evt.get("command_line", "").lower()
            uid = evt.get("uid", 1000)
            euid = evt.get("euid", 1000)

            is_suspicious = False
            reasons = []
            mitre_techniques = []
            max_severity = "LOW"

            # Detect EUID mismatch (SUID privilege escalation)
            if uid != 0 and euid == 0:
                is_suspicious = True
                privilege_esc_count += 1
                reasons.append("EUID mismatch (non-root UID running as EUID 0)")
                mitre_techniques.append("T1548.001")
                max_severity = "HIGH"

            # Check pattern matches
            for pat in _SUSPICIOUS_PATTERNS:
                if pat["pattern"].lower() in cmd:
                    is_suspicious = True
                    reasons.append(pat["description"])
                    mitre_techniques.append(pat["mitre_technique"])
                    if pat["severity"] == "CRITICAL" or max_severity != "CRITICAL":
                        max_severity = pat["severity"]

            if is_suspicious:
                suspicious_count += 1

            analyzed_events.append(
                {
                    **evt,
                    "is_suspicious": is_suspicious,
                    "reasons": reasons,
                    "mitre_techniques": mitre_techniques,
                    "severity": max_severity if is_suspicious else "INFO",
                }
            )

        report = {
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "total_commands": len(events),
            "suspicious_commands": suspicious_count,
            "privilege_escalations": privilege_esc_count,
            "events": analyzed_events,
        }

        _AUDIT_LOG_STORE.append(report)
        return report

    @staticmethod
    def get_tenant_command_audits(tenant_id: str) -> list[dict[str, Any]]:
        """Retrieves command audit history for a tenant."""
        records = [r for r in _AUDIT_LOG_STORE if r.get("tenant_id") == tenant_id]
        if not records:
            # Generate default audit report
            events = CommandAuditor().audit_executed_commands()
            return [CommandAuditService.analyze_command_events("agent-dev-01", tenant_id, events)]
        return records
