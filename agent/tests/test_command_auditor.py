"""
Unit & Integration Tests for Command Execution & Syscall Auditor.
"""

from app.services.command_audit_service import CommandAuditService

from arka_agent.collectors.command_auditor import CommandAuditor


def test_command_auditor_collector():
    """Verifies CommandAuditor collects process execution events."""
    auditor = CommandAuditor(agent_id="test-agent", tenant_id="tenant-beta")
    snapshot = auditor.scan_command_telemetry()

    assert snapshot["agent_id"] == "test-agent"
    assert snapshot["tenant_id"] == "tenant-beta"
    assert snapshot["event_count"] == 3
    assert isinstance(snapshot["events"], list)


def test_command_audit_service_detection():
    """Verifies CommandAuditService flags suspicious executions and privilege escalation."""
    auditor = CommandAuditor(agent_id="agent-01", tenant_id="tenant-beta")
    raw_events = auditor.audit_executed_commands()

    report = CommandAuditService.analyze_command_events("agent-01", "tenant-beta", raw_events)

    assert report["total_commands"] == 3
    assert report["suspicious_commands"] == 2
    assert report["privilege_escalations"] == 1

    suspicious = [e for e in report["events"] if e["is_suspicious"]]
    assert len(suspicious) == 2

    # Check MITRE techniques tagged
    all_mitre = [t for e in suspicious for t in e["mitre_techniques"]]
    assert "T1003.008" in all_mitre or "T1059.004" in all_mitre
