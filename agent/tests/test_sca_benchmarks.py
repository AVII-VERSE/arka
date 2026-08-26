"""
Unit & Integration Tests for Security Configuration Assessment (SCA) & CIS Benchmarks Engine.
"""

from app.services.sca_engine import SCAEngine

from arka_agent.collectors.sca import SCAScanner


def test_sca_scanner_execution():
    """Verifies SCAScanner evaluates CIS benchmark checks and calculates compliance score."""
    scanner = SCAScanner(agent_id="test-agent", tenant_id="tenant-alpha")
    report = scanner.run_assessment()

    assert report["agent_id"] == "test-agent"
    assert report["tenant_id"] == "tenant-alpha"
    assert "compliance_score" in report
    assert isinstance(report["compliance_score"], float)
    assert report["summary"]["total_checks"] == 3
    assert len(report["checks"]) == 3


def test_sca_engine_aggregation():
    """Verifies SCAEngine aggregates endpoint reports and returns tenant compliance data."""
    mock_report = {
        "policy_id": "cis_test",
        "policy_name": "Test CIS Policy",
        "agent_id": "test-agent-02",
        "tenant_id": "tenant-beta",
        "timestamp": "2026-08-26T12:00:00Z",
        "compliance_score": 100.0,
        "summary": {"total_checks": 3, "passed": 3, "failed": 0, "not_applicable": 0},
        "checks": [],
    }

    SCAEngine.register_report("test-agent-02", mock_report)
    tenant_reports = SCAEngine.get_tenant_reports("tenant-beta")

    assert len(tenant_reports) == 1
    assert tenant_reports[0]["agent_id"] == "test-agent-02"
    assert tenant_reports[0]["compliance_score"] == 100.0
