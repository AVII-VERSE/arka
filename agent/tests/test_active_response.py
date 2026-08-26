"""
Unit & Integration Tests for Automated Active Response & Endpoint Threat Containment.
"""

from app.services.active_response_service import ActiveResponseService

from arka_agent.active_response import ActiveResponseExecutor


def test_active_response_executor():
    """Verifies ActiveResponseExecutor executes IP blocking and process containment commands."""
    executor = ActiveResponseExecutor(agent_id="test-agent", tenant_id="tenant-alpha")

    res_block = executor.block_ip("192.168.1.105")
    assert res_block["status"] == "SUCCESS"
    assert res_block["action"] == "block_ip"
    assert res_block["target"] == "192.168.1.105"

    res_kill = executor.kill_process(999999)
    assert res_kill["action"] == "kill_process"
    assert res_kill["status"] == "NOT_FOUND"


def test_active_response_service_dispatch():
    """Verifies ActiveResponseService evaluates CRITICAL alerts and triggers containment."""
    mock_alert = {
        "id": "alert-test-99",
        "tenant_id": "tenant-gamma",
        "agent_id": "agent-dev-01",
        "severity": "CRITICAL",
        "rule_code": "BRUTE_FORCE_LOGIN",
        "source_ip": "10.0.0.55",
    }

    entry = ActiveResponseService.dispatch_alert_response(mock_alert)
    assert entry is not None
    assert entry["action"] == "block_ip"
    assert entry["target"] == "10.0.0.55"

    logs = ActiveResponseService.get_tenant_logs("tenant-gamma")
    assert len(logs) == 1
    assert logs[0]["target"] == "10.0.0.55"
