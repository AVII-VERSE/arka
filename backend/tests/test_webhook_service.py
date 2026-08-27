"""
Unit & Integration Tests for Real-Time Webhook Alerting & Incident Notification Engine.
"""

from app.services.webhook_service import WebhookService


def test_webhook_registration():
    """Verifies registering a new webhook alerting destination."""
    webhook = WebhookService.register_webhook(
        tenant_id="tenant-delta",
        name="Security Operations Teams",
        target_url="https://outlook.office.com/webhook/test",
        secret="test_secret_key_456",
        events=["alert.critical"],
        format_type="teams",
    )

    assert webhook["name"] == "Security Operations Teams"
    assert webhook["tenant_id"] == "tenant-delta"
    assert webhook["is_active"] is True


def test_webhook_hmac_signature():
    """Verifies HMAC-SHA256 signature calculation."""
    sig = WebhookService.generate_hmac_signature("secret_123", '{"test": "payload"}')
    assert len(sig) == 64
    assert isinstance(sig, str)


def test_alert_dispatch():
    """Verifies alert dispatch generates signed notifications for active webhooks."""
    WebhookService.register_webhook(
        tenant_id="tenant-echo",
        name="Slack SOC Channel",
        target_url="https://hooks.slack.com/services/test",
        secret="slack_secret_789",
        events=["alert.high"],
    )

    sample_alert = {
        "rule_id": "R1001",
        "severity": "HIGH",
        "title": "Brute Force Attack Detected",
        "description": "10 failed SSH logins from IP 192.168.1.50",
    }

    dispatches = WebhookService.dispatch_alert("tenant-echo", sample_alert)
    assert len(dispatches) >= 1
    assert dispatches[0]["status"] == "DELIVERED"
    assert dispatches[0]["signature"].startswith("sha256=")
