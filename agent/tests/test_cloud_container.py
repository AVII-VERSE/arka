"""
Unit & Integration Tests for Container & Cloud Security Telemetry Harvesters.
"""

from app.services.cloud_container_service import CloudContainerService

from arka_agent.collectors.cloud_container import CloudContainerCollector


def test_cloud_container_collector():
    """Verifies CloudContainerCollector collects container and cloud events."""
    collector = CloudContainerCollector(agent_id="test-agent", tenant_id="tenant-gamma")
    snapshot = collector.scan_cloud_container_telemetry()

    assert snapshot["agent_id"] == "test-agent"
    assert snapshot["tenant_id"] == "tenant-gamma"
    assert snapshot["container_count"] == 2
    assert snapshot["cloud_event_count"] == 2
    assert isinstance(snapshot["containers"], list)
    assert isinstance(snapshot["cloud_events"], list)


def test_cloud_container_service_risk_detection():
    """Verifies CloudContainerService identifies privileged mode, host network, and S3 public policies."""
    collector = CloudContainerCollector(agent_id="agent-01", tenant_id="tenant-gamma")
    c_events = collector.get_container_events()
    cloud_events = collector.get_cloud_audit_events()

    report = CloudContainerService.analyze_container_telemetry(
        "agent-01", "tenant-gamma", c_events, cloud_events
    )

    assert report["total_containers"] == 2
    assert report["flagged_containers_count"] == 1
    assert report["flagged_cloud_events_count"] == 2

    flagged_c = report["flagged_containers"][0]
    assert flagged_c["is_high_risk"] is True
    assert "Container executing in Privileged Mode (--privileged)" in flagged_c["risk_factors"]
    assert "CAP_SYS_ADMIN Linux capability granted (container escape risk)" in flagged_c["risk_factors"]
