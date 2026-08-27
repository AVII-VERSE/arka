"""
Unit & Integration Tests for Threat Hunting Playbooks Engine.
"""

from app.services.threat_hunting_service import (
    BUILTIN_PLAYBOOKS,
    ThreatHuntingService,
)


def test_builtin_playbook_library_seeded():
    """Verifies that built-in playbooks are auto-seeded for new tenants."""
    playbooks = ThreatHuntingService.list_playbooks("tenant-hunt-01")
    assert len(playbooks) == len(BUILTIN_PLAYBOOKS)
    assert all(pb["is_builtin"] for pb in playbooks)
    assert all(pb["tenant_id"] == "tenant-hunt-01" for pb in playbooks)


def test_get_builtin_playbook():
    """Verifies retrieving a specific built-in playbook by ID."""
    pb = ThreatHuntingService.get_playbook("tenant-hunt-02", "PB-LATERAL-MOVEMENT-001")
    assert pb is not None
    assert pb["name"] == "Lateral Movement via Remote Services"
    assert pb["mitre_tactic"] == "Lateral Movement"
    assert len(pb["steps"]) == 3


def test_get_nonexistent_playbook():
    """Verifies None returned for non-existent playbook."""
    result = ThreatHuntingService.get_playbook("tenant-hunt-03", "PB-NONEXISTENT")
    assert result is None


def test_create_custom_playbook():
    """Verifies creating a custom threat hunting playbook."""
    custom = ThreatHuntingService.create_playbook(
        "tenant-hunt-04",
        {
            "name": "Insider Threat Detection",
            "description": "Hunt for insider threat indicators.",
            "mitre_tactic": "Collection",
            "mitre_technique_ids": ["T1119"],
            "hypothesis": "An insider is collecting sensitive data.",
            "steps": [
                {
                    "step_id": 1,
                    "action": "Check for mass file access patterns",
                    "query_hint": "event.type == 'file_access' AND count > 100",
                    "expected_evidence": "Bulk file reads from sensitive directories",
                }
            ],
            "severity": "HIGH",
            "tags": ["insider-threat"],
        },
    )
    assert custom["playbook_id"].startswith("PB-CUSTOM-")
    assert custom["is_builtin"] is False
    assert custom["name"] == "Insider Threat Detection"

    # Verify it appears in list
    all_pbs = ThreatHuntingService.list_playbooks("tenant-hunt-04")
    assert any(p["playbook_id"] == custom["playbook_id"] for p in all_pbs)


def test_execute_playbook():
    """Verifies executing a playbook produces structured execution record."""
    execution = ThreatHuntingService.execute_playbook(
        "tenant-hunt-05",
        "PB-CREDENTIAL-DUMPING-001",
        analyst="Alice SOC",
    )
    assert execution["status"] == "COMPLETED"
    assert execution["playbook_id"] == "PB-CREDENTIAL-DUMPING-001"
    assert execution["analyst"] == "Alice SOC"
    assert execution["mitre_tactic"] == "Credential Access"
    assert len(execution["step_results"]) == 3
    assert all(s["status"] == "COMPLETED" for s in execution["step_results"])
    assert execution["execution_id"].startswith("exec-")


def test_execute_nonexistent_playbook():
    """Verifies error returned when executing a non-existent playbook."""
    result = ThreatHuntingService.execute_playbook("tenant-hunt-06", "PB-FAKE")
    assert "error" in result


def test_list_executions():
    """Verifies listing execution records after running a playbook."""
    ThreatHuntingService.execute_playbook("tenant-hunt-07", "PB-DATA-EXFILTRATION-001")
    executions = ThreatHuntingService.list_executions("tenant-hunt-07")
    assert len(executions) >= 1
    assert executions[0]["playbook_id"] == "PB-DATA-EXFILTRATION-001"


def test_get_execution():
    """Verifies retrieving a specific execution record."""
    ex = ThreatHuntingService.execute_playbook("tenant-hunt-08", "PB-PERSISTENCE-001")
    result = ThreatHuntingService.get_execution("tenant-hunt-08", ex["execution_id"])
    assert result is not None
    assert result["execution_id"] == ex["execution_id"]


def test_get_nonexistent_execution():
    """Verifies None returned for non-existent execution."""
    result = ThreatHuntingService.get_execution("tenant-hunt-09", "exec-fake")
    assert result is None


def test_tenant_isolation():
    """Verifies playbooks and executions are tenant-isolated."""
    ThreatHuntingService.create_playbook(
        "tenant-iso-A",
        {"name": "Tenant A Hunt", "description": "A-only", "mitre_tactic": "Discovery",
         "hypothesis": "test", "steps": [], "severity": "LOW", "tags": []},
    )
    pbs_a = ThreatHuntingService.list_playbooks("tenant-iso-A")
    pbs_b = ThreatHuntingService.list_playbooks("tenant-iso-B")

    custom_a = [p for p in pbs_a if not p["is_builtin"]]
    custom_b = [p for p in pbs_b if not p["is_builtin"]]

    assert len(custom_a) == 1
    assert len(custom_b) == 0
