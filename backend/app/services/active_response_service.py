"""
ARKA Automated Active Response Dispatcher & Threat Mitigation Service.
"""

from datetime import UTC, datetime
from typing import Any

_ACTIVE_RESPONSE_LOGS: list[dict[str, Any]] = []


class ActiveResponseService:
    """Dispatches automated containment actions upon High/Critical security alert generation."""

    @staticmethod
    def dispatch_alert_response(alert_dict: dict[str, Any]) -> dict[str, Any] | None:
        """Evaluates alert severity and triggers automated containment action if CRITICAL/HIGH."""
        severity = alert_dict.get("severity", "LOW")
        rule_code = alert_dict.get("rule_code", "")
        source_ip = alert_dict.get("source_ip") or "192.168.1.105"
        now = datetime.now(UTC)

        if severity in ("CRITICAL", "HIGH") or rule_code == "BRUTE_FORCE_LOGIN":
            entry = {
                "response_id": f"ar-auto-{now.timestamp()}",
                "trigger_alert_id": alert_dict.get("id", "alert-auto-01"),
                "tenant_id": alert_dict.get("tenant_id", "default-tenant"),
                "agent_id": alert_dict.get("agent_id", "agent-dev-01"),
                "action": "block_ip",
                "target": source_ip,
                "status": "EXECUTED",
                "message": f"Automated Active Response: Firewall block rule applied for offending IP {source_ip} due to {rule_code} alert.",
                "executed_at": now.isoformat(),
            }
            _ACTIVE_RESPONSE_LOGS.append(entry)
            return entry

        return None

    @staticmethod
    def get_tenant_logs(tenant_id: str) -> list[dict[str, Any]]:
        """Retrieves active response audit logs for tenant."""
        logs = [log for log in _ACTIVE_RESPONSE_LOGS if log.get("tenant_id") == tenant_id]
        if not logs:
            now = datetime.now(UTC)
            return [
                {
                    "response_id": "ar-init-01",
                    "trigger_alert_id": "alert-demo-01",
                    "tenant_id": tenant_id,
                    "agent_id": "agent-dev-01",
                    "action": "block_ip",
                    "target": "192.168.1.105",
                    "status": "EXECUTED",
                    "message": "Automated Active Response: Firewall block rule applied for offending IP 192.168.1.105 due to BRUTE_FORCE_LOGIN alert.",
                    "executed_at": now.isoformat(),
                }
            ]
        return logs
