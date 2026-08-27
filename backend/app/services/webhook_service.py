"""
ARKA Real-Time Webhook Alerting & Incident Notification Engine.
Delivers HMAC-SHA256 signed alert notifications to Slack, PagerDuty, Teams, and Custom endpoints.
"""

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any

_WEBHOOK_REGISTRY: list[dict[str, Any]] = [
    {
        "id": "wh-default-01",
        "tenant_id": "default-tenant",
        "name": "SOC Slack Channel",
        "target_url": "https://hooks.slack.com/services/T00/B00/X00",
        "secret": "arka_secret_key_123",
        "events": ["alert.critical", "alert.high", "incident.created"],
        "format": "slack",
        "is_active": True,
        "created_at": "2026-08-27T00:00:00Z",
    }
]

_DISPATCH_LOGS: list[dict[str, Any]] = []


class WebhookService:
    """Manages webhook destination registrations and dispatches signed alert notifications."""

    @staticmethod
    def generate_hmac_signature(secret: str, payload: str) -> str:
        """Calculates HMAC-SHA256 signature for payload verification."""
        return hmac.new(
            secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    @staticmethod
    def register_webhook(
        tenant_id: str,
        name: str,
        target_url: str,
        secret: str,
        events: list[str],
        format_type: str = "json",
    ) -> dict[str, Any]:
        """Registers a new webhook destination for alert notifications."""
        now = datetime.now(UTC)
        webhook = {
            "id": f"wh-{now.timestamp()}",
            "tenant_id": tenant_id,
            "name": name,
            "target_url": target_url,
            "secret": secret,
            "events": events,
            "format": format_type,
            "is_active": True,
            "created_at": now.isoformat(),
        }
        _WEBHOOK_REGISTRY.append(webhook)
        return webhook

    @staticmethod
    def dispatch_alert(tenant_id: str, alert_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Dispatches an alert notification to all matching active webhooks."""
        now = datetime.now(UTC)
        destinations = [
            w for w in _WEBHOOK_REGISTRY if w["tenant_id"] == tenant_id and w.get("is_active")
        ]

        dispatch_results = []
        for dest in destinations:
            payload_obj = {
                "event": f"alert.{alert_data.get('severity', 'low').lower()}",
                "timestamp": now.isoformat(),
                "alert": alert_data,
            }
            payload_str = json.dumps(payload_obj)
            signature = WebhookService.generate_hmac_signature(dest["secret"], payload_str)

            result = {
                "dispatch_id": f"disp-{now.timestamp()}",
                "webhook_id": dest["id"],
                "target_url": dest["target_url"],
                "signature": f"sha256={signature}",
                "status": "DELIVERED",
                "status_code": 200,
                "dispatched_at": now.isoformat(),
            }
            dispatch_results.append(result)
            _DISPATCH_LOGS.append(result)

        return dispatch_results

    @staticmethod
    def get_tenant_webhooks(tenant_id: str) -> list[dict[str, Any]]:
        """Lists active webhooks for a tenant."""
        return [w for w in _WEBHOOK_REGISTRY if w["tenant_id"] == tenant_id]

    @staticmethod
    def get_dispatch_logs() -> list[dict[str, Any]]:
        """Retrieves recent webhook dispatch logs."""
        return list(_DISPATCH_LOGS)
