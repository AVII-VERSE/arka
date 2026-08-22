"""
Unit & Integration Tests for OpenSearch Time-Series Event Indexing & Search Engine.
"""

from datetime import UTC, datetime

from app.schemas.schemas import NormalizedEvent, SeverityEnum
from app.services.opensearch_service import OpenSearchEventService


def test_opensearch_index_naming_pattern():
    """Verifies index naming pattern follows arka-events-{tenant_id}-{yyyy.mm}."""
    service = OpenSearchEventService()
    now = datetime(2026, 8, 22, 12, 0, 0, tzinfo=UTC)
    index_name = service.get_index_name("tenant-alpha", timestamp=now)
    assert index_name == "arka-events-tenant-alpha-2026.08"


def test_opensearch_ecs_mapping_structure():
    """Verifies OpenSearch ECS mapping structure definition."""
    service = OpenSearchEventService()
    mapping = service.get_ecs_index_mapping()
    props = mapping["mappings"]["properties"]

    assert props["event_id"]["type"] == "keyword"
    assert props["source_ip"]["type"] == "ip"
    assert props["destination_ip"]["type"] == "ip"
    assert props["timestamp"]["type"] == "date"
    assert props["message"]["type"] == "text"


def test_opensearch_indexing_and_search_query():
    """Verifies indexing security events and executing search queries with filters."""
    service = OpenSearchEventService()
    now = datetime.now(UTC)

    event1 = NormalizedEvent(
        event_id="evt-os-01",
        tenant_id="tenant-alpha",
        agent_id="agent-01",
        timestamp=now,
        source_type="windows_event_log",
        source_ip="192.168.1.105",
        host="DC01.CYBERCORP.LOCAL",
        user="administrator",
        event_type="authentication",
        action="logon_failed",
        severity=SeverityEnum.HIGH,
        message="Failed logon attempt for administrator",
    )

    event2 = NormalizedEvent(
        event_id="evt-os-02",
        tenant_id="tenant-alpha",
        agent_id="agent-01",
        timestamp=now,
        source_type="windows_event_log",
        source_ip="10.0.0.50",
        host="WORKSTATION-05",
        user="jdoe",
        event_type="process",
        action="powershell_exec",
        severity=SeverityEnum.CRITICAL,
        message="Suspicious encoded PowerShell command executed",
        process="powershell.exe -EncodedCommand QW50aWdyYXZpdHk=",
    )

    count = service.bulk_index_events([event1, event2])
    assert count == 2

    # Query by host
    results_host = service.search_events(tenant_id="tenant-alpha", host="DC01.CYBERCORP.LOCAL")
    assert len(results_host) == 1
    assert results_host[0]["event_id"] == "evt-os-01"

    # Full-text Lucene query search
    results_search = service.search_events(tenant_id="tenant-alpha", search_query="PowerShell")
    assert len(results_search) == 1
    assert results_search[0]["event_id"] == "evt-os-02"

    # Multi-tenant boundary check
    results_tenant_b = service.search_events(tenant_id="tenant-beta")
    assert len(results_tenant_b) == 0
