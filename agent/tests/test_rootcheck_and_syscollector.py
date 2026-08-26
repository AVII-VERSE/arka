"""
Unit & Integration Tests for Rootcheck Security Scanner & Syscollector System Inventory.
"""

from arka_agent.collectors.rootcheck import RootcheckScanner
from arka_agent.collectors.syscollector import SyscollectorHarvester


def test_rootcheck_scanner_execution(tmp_path):
    """Verifies RootcheckScanner detects suspicious rootkit artifact files."""
    test_file = tmp_path / ".hidden"
    test_file.write_text("rootkit_payload", encoding="utf-8")

    scanner = RootcheckScanner(agent_id="test-agent", tenant_id="tenant-alpha")
    scanner.suspicious_paths = [str(test_file)]

    events = scanner.scan_suspicious_files()
    assert len(events) == 1
    assert events[0]["event_type"] == "rootkit_detection"
    assert events[0]["severity"] == "CRITICAL"
    assert events[0]["metadata"]["suspicious_path"] == str(test_file)


def test_syscollector_inventory_harvesting():
    """Verifies SyscollectorHarvester gathers hardware, OS, and network interfaces."""
    harvester = SyscollectorHarvester(agent_id="test-agent", tenant_id="tenant-alpha")
    snapshot = harvester.collect_inventory()

    assert snapshot["agent_id"] == "test-agent"
    assert snapshot["tenant_id"] == "tenant-alpha"
    assert "cpu_cores_logical" in snapshot["hardware"]
    assert "os_name" in snapshot["os"]
    assert isinstance(snapshot["network_interfaces"], list)
    assert isinstance(snapshot["running_processes"], list)
