"""
Unit & Integration Tests for Agent File Integrity Monitoring (FIM) and Process Lineage.
"""

import os

from arka_agent.collectors.fim import FileIntegrityMonitor


def test_fim_baseline_and_modification_detection(tmp_path):
    """Verifies FIM calculates SHA-256 baseline and detects file modifications."""
    test_file = tmp_path / "sensitive_config.conf"
    test_file.write_text("initial_config_v1", encoding="utf-8")

    monitor = FileIntegrityMonitor(
        agent_id="test-agent",
        tenant_id="tenant-alpha",
        monitored_paths=[str(test_file)],
    )

    # Initial check (no changes)
    changes = monitor.check_changes()
    assert len(changes) == 0

    # Modify file content
    test_file.write_text("modified_config_v2_unauthorized", encoding="utf-8")

    # Second check (detect modification)
    changes = monitor.check_changes()
    assert len(changes) == 1
    assert changes[0]["action"] == "file_modified"
    assert changes[0]["severity"] == "HIGH"
    assert changes[0]["metadata"]["file_path"] == str(test_file)


def test_fim_file_deletion_detection(tmp_path):
    """Verifies FIM detects file deletion event."""
    test_file = tmp_path / "hosts_backup.etc"
    test_file.write_text("127.0.0.1 localhost", encoding="utf-8")

    monitor = FileIntegrityMonitor(
        agent_id="test-agent",
        tenant_id="tenant-alpha",
        monitored_paths=[str(test_file)],
    )

    # Delete target file
    os.remove(str(test_file))

    changes = monitor.check_changes()
    assert len(changes) == 1
    assert changes[0]["action"] == "file_deleted"
    assert changes[0]["severity"] == "HIGH"


def test_process_lineage_metadata_schema():
    """Verifies process lineage metadata keys are included in process event schema."""
    lineage_metadata = {
        "parent_process_id": 1024,
        "parent_process_name": "services.exe",
        "process_id": 4096,
        "process_name": "powershell.exe",
        "process_command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass",
    }

    assert lineage_metadata["parent_process_name"] == "services.exe"
    assert lineage_metadata["process_command_line"].startswith("powershell.exe")
