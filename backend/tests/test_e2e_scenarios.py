# ruff: noqa: PLR0915
"""
Tier 4 Real-World Application Scenarios E2E Test Suite for ARKA Enterprise SIEM & XDR Platform.

Covers all 5 Tier 4 Real-World Scenarios from TEST_INFRA.md:
1. Log4Shell RCE Exploitation & Automated Containment (CVE-2021-44228)
2. Kernel Rootkit Persistence & Backdoor C2 Socket (Rootcheck & Quarantine Vault)
3. CIS Benchmark Drift & Baron Samedit Privilege Escalation (CVE-2021-3156 & Incident Management)
4. High-Volume Endpoint Brute Force Attack (Ingestion, Rule BRUTE_FORCE_LOGIN, Automated Active Response)
5. Agent Offline Buffering & Resilient Re-synchronization (SQLiteQueue FIFO buffer, HTTP transport, multi-collector batch ingest)
"""

import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from arka_agent.active_response import ActiveResponseExecutor
from arka_agent.buffer.sqlite_queue import SQLiteQueue
from arka_agent.collectors.rootcheck import RootcheckScanner
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import (
    ActiveResponseActionEnum,
    ActiveResponseTaskStatusEnum,
    Agent,
    AgentStatusEnum,
    Alert,
    AlertStatusEnum,
    AuditLog,
    IncidentStatusEnum,
    SeverityEnum,
    Tenant,
    User,
    VulnerabilityFinding,
    VulnerabilityStatusEnum,
)
from app.schemas.schemas import (
    ActiveResponseStatusUpdate,
    ActiveResponseTriggerRequest,
    IncidentCreate,
    IncidentUpdateStatus,
    InventorySnapshotPayload,
    VulnerabilityScanPayload,
)
from app.services.active_response_service import ActiveResponseService
from app.services.detection_engine import DetectionEngine
from app.services.kafka_pipeline import kafka_producer


@pytest.mark.asyncio
async def test_scenario_log4shell_rce_and_containment(
    client: AsyncClient,
    db_session: AsyncSession,
    test_tenant: Tenant,
    test_user: User,
    auth_headers: dict[str, str],
    tmp_path: Path,
):
    """
    Scenario 1: Log4Shell RCE Exploitation & Automated Containment (CVE-2021-44228).
    Workflow:
    - Syscollector ingests software inventory with vulnerable Apache Log4j 2.14.0 and running Java process.
    - Vulnerability Engine correlates inventory against CVE database and identifies CVE-2021-44228 (Critical, CVSS 10.0).
    - Automated Critical Alert is generated in database.
    - Active Response dispatches containment tasks: IP block against attacker C2 (198.51.100.42) and process termination (PID 4422).
    - Agent daemon polls pending containment tasks, executes ActiveResponseExecutor, and submits callback results.
    - AuditLog records full containment lifecycle and finding status is patched to MITIGATED.
    """
    agent_id = "agent-log4j-srv01"
    attacker_ip = "198.51.100.42"
    malicious_pid = 4422

    # 1. Enroll agent
    agent = Agent(
        id=agent_id,
        tenant_id=test_tenant.id,
        hostname="srv-app-prod01",
        ip_address="10.10.20.50",
        os_type="linux",
        os_version="Ubuntu 22.04 LTS",
        status=AgentStatusEnum.ONLINE,
    )
    db_session.add(agent)
    await db_session.commit()

    # 2. Ingest Syscollector snapshot with vulnerable Log4j package and running process
    snapshot_payload = InventorySnapshotPayload(
        snapshot_id=f"snap-{uuid.uuid4()}",
        agent_id=agent_id,
        tenant_id=test_tenant.id,
        timestamp=datetime.now(UTC).isoformat(),
        hardware={
            "cpu_cores_logical": 8,
            "cpu_cores_physical": 4,
            "cpu_architecture": "x86_64",
            "ram_total_gb": 32.0,
            "disks": [{"device": "/dev/sda1", "mountpoint": "/", "total_gb": 500.0}],
        },
        os={
            "hostname": "srv-app-prod01",
            "os_name": "Linux",
            "os_release": "5.15.0-89-generic",
            "os_version": "Ubuntu 22.04 LTS",
            "kernel_architecture": "x86_64",
        },
        packages=[
            {"name": "log4j", "version": "2.14.0", "vendor": "Apache", "architecture": "all"},
            {"name": "openjdk", "version": "11.0.11", "vendor": "Ubuntu", "architecture": "amd64"},
            {"name": "bash", "version": "5.1.16", "vendor": "Ubuntu", "architecture": "amd64"},
        ],
        network_interfaces=[
            {
                "interface_name": "eth0",
                "ipv4_address": "10.10.20.50",
                "mac_address": "00:50:56:a1:b2:c3",
                "status": "UP",
            }
        ],
        open_ports=[{"protocol": "tcp", "local_ip": "0.0.0.0", "local_port": 8080, "state": "LISTEN", "process_name": "java", "pid": malicious_pid}],
        running_processes=[
            {
                "pid": malicious_pid,
                "name": "java",
                "cmdline": "java -jar /opt/app/vulnerable-app.jar",
                "username": "appuser",
                "cpu_percent": 12.5,
                "memory_percent": 8.0,
            }
        ],
    )

    snap_resp = await client.post(
        "/api/v1/inventory/snapshot",
        json=snapshot_payload.model_dump(),
        headers=auth_headers,
    )
    assert snap_resp.status_code == 201
    assert snap_resp.json()["packages_ingested"] == 3

    # 3. Vulnerability Scan & Correlation
    scan_payload = VulnerabilityScanPayload(
        agent_id=agent_id,
        tenant_id=test_tenant.id,
        packages=[
            {"name": "log4j", "version": "2.14.0"},
            {"name": "openjdk", "version": "11.0.11"},
            {"name": "bash", "version": "5.1.16"},
        ],
    )
    scan_resp = await client.post(
        "/api/v1/vulnerabilities/scan",
        json=scan_payload.model_dump(),
        headers=auth_headers,
    )
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    assert scan_data["status"] == "success"
    assert scan_data["critical_count"] >= 1

    # Verify Log4Shell finding in database
    finding_query = await db_session.execute(
        select(VulnerabilityFinding).where(
            VulnerabilityFinding.agent_id == agent_id,
            VulnerabilityFinding.cve_id == "CVE-2021-44228",
        )
    )
    log4j_finding = finding_query.scalar_one()
    assert log4j_finding.severity == SeverityEnum.CRITICAL
    assert log4j_finding.cvss_score == 10.0
    assert log4j_finding.status == VulnerabilityStatusEnum.ACTIVE

    # 4. Trigger Active Response Containment Actions:
    # A) Block Attacker C2 IP
    ip_block_req = ActiveResponseTriggerRequest(
        agent_id=agent_id,
        action=ActiveResponseActionEnum.BLOCK_IP,
        target=attacker_ip,
        parameters={"duration_seconds": 3600, "reason": "Log4Shell JNDI exploit C2 containment"},
    )
    ip_task_resp = await client.post(
        "/api/v1/active_response/trigger",
        json=ip_block_req.model_dump(),
        headers=auth_headers,
    )
    assert ip_task_resp.status_code == 201
    ip_task_id = ip_task_resp.json()["id"]

    # B) Terminate Compromised Java Process
    proc_kill_req = ActiveResponseTriggerRequest(
        agent_id=agent_id,
        action=ActiveResponseActionEnum.KILL_PROCESS,
        target=str(malicious_pid),
        parameters={"recursive": True, "reason": "Terminate exploited Java runtime"},
    )
    proc_task_resp = await client.post(
        "/api/v1/active_response/trigger",
        json=proc_kill_req.model_dump(),
        headers=auth_headers,
    )
    assert proc_task_resp.status_code == 201
    proc_task_id = proc_task_resp.json()["id"]

    # 5. Agent polls pending containment tasks
    poll_resp = await client.get(
        f"/api/v1/active_response/agents/{agent_id}/pending",
        headers=auth_headers,
    )
    assert poll_resp.status_code == 200
    pending_tasks = poll_resp.json()
    assert len(pending_tasks) >= 2
    task_ids = {t["id"] for t in pending_tasks}
    assert ip_task_id in task_ids
    assert proc_task_id in task_ids

    # 6. Agent executes ActiveResponseExecutor (dry_run=True for safe CI environment)
    executor = ActiveResponseExecutor(
        agent_id=agent_id,
        tenant_id=test_tenant.id,
        dry_run=True,
    )
    block_res = executor.block_ip(attacker_ip, duration_seconds=3600)
    assert block_res["status"] == "SUCCESS"

    kill_res = executor.kill_process(malicious_pid)
    assert kill_res["status"] in ("SUCCESS", "NOT_FOUND")

    # 7. Agent submits containment execution callbacks
    for t_id, action_name in [(ip_task_id, "block_ip"), (proc_task_id, "kill_process")]:
        update_data = ActiveResponseStatusUpdate(
            task_id=t_id,
            status=ActiveResponseTaskStatusEnum.SUCCESS,
            exit_code=0,
            stdout=f"Active response containment for {action_name} executed successfully.",
            message=f"Containment action {action_name} applied.",
        )
        res_cb = await client.post(
            f"/api/v1/active_response/tasks/{t_id}/result",
            json=update_data.model_dump(),
            headers=auth_headers,
        )
        assert res_cb.status_code == 200
        assert res_cb.json()["status"] == "SUCCESS"

    # 8. Verify AuditLog entries created in database
    audit_query = await db_session.execute(
        select(AuditLog).where(
            AuditLog.tenant_id == test_tenant.id,
            AuditLog.resource_type == "ActiveResponseTask",
        )
    )
    audits = audit_query.scalars().all()
    assert len(audits) >= 4  # 2 creations + 2 results
    assert any(a.action == "CREATE_ACTIVE_RESPONSE_TASK" for a in audits)
    assert any(a.action == "ACTIVE_RESPONSE_TASK_RESULT_RECORDED" for a in audits)

    # 9. Update Vulnerability Finding Lifecycle (ACTIVE -> MITIGATED)
    status_patch_resp = await client.patch(
        f"/api/v1/vulnerabilities/findings/{log4j_finding.id}/status",
        json={"status": "MITIGATED", "note": "Log4j upgraded to version 2.17.1"},
        headers=auth_headers,
    )
    assert status_patch_resp.status_code == 200
    assert status_patch_resp.json()["status"] == "MITIGATED"

    await db_session.refresh(log4j_finding)
    assert log4j_finding.status == VulnerabilityStatusEnum.MITIGATED


@pytest.mark.asyncio
async def test_scenario_rootkit_persistence_and_quarantine(
    client: AsyncClient,
    db_session: AsyncSession,
    test_tenant: Tenant,
    test_user: User,
    auth_headers: dict[str, str],
    tmp_path: Path,
):
    """
    Scenario 2: Kernel Rootkit Persistence & Backdoor C2 Socket.
    Workflow:
    - Rootcheck scanner audits file integrity and network listeners on agent host.
    - Scanner identifies hidden rootkit kernel module artifact (diamorphine.ko) and backdoor listener on port 31337.
    - SIEM registers threat alerts (ROOTKIT_BACKDOOR_DETECTED, UNMAPPED_BACKDOOR_SOCKET) with MITRE T1014 / T1571.
    - Automated Active Response dispatches file quarantine task and C2 IP block.
    - Agent ActiveResponseExecutor securely moves artifact to quarantine vault, calculates SHA-256 hash, and generates manifest.
    - Agent reports execution callback to backend, and unquarantine restoration is validated.
    """
    agent_id = "agent-rootkit-srv02"
    quarantine_vault = tmp_path / "quarantine_vault"

    # 1. Enroll agent
    agent = Agent(
        id=agent_id,
        tenant_id=test_tenant.id,
        hostname="srv-db-sec01",
        ip_address="192.168.1.150",
        os_type="linux",
        os_version="Debian 12",
        status=AgentStatusEnum.ONLINE,
    )
    db_session.add(agent)
    await db_session.commit()

    # 2. Simulate Rootcheck Scanner Anomaly Detection
    sample_rootkit = tmp_path / "diamorphine.ko"
    sample_rootkit.write_bytes(b"\x7fELF_ROOTKIT_PAYLOAD_DIAMORPHINE_31337")

    scanner = RootcheckScanner(
        agent_id=agent_id,
        tenant_id=test_tenant.id,
        suspicious_paths=[str(sample_rootkit)],
    )

    # A) File Anomaly Scan
    file_findings = scanner.scan_suspicious_files(paths=[str(sample_rootkit)])
    assert len(file_findings) >= 1
    assert file_findings[0]["severity"] == "CRITICAL"
    assert file_findings[0]["action"] == "suspicious_file_found"
    assert file_findings[0]["metadata"]["mitre_technique"] == "T1014"

    # B) Port Anomaly Scan (Simulate unmapped listening backdoor socket on port 31337)
    mock_conn = MagicMock()
    mock_conn.status = "LISTEN"
    mock_conn.laddr = MagicMock(ip="0.0.0.0", port=31337)
    mock_conn.pid = None
    mock_conn.type = 1  # SOCK_STREAM

    port_findings = scanner.scan_listening_ports(custom_connections=[mock_conn])
    assert len(port_findings) >= 1
    backdoor_event = next((f for f in port_findings if f["metadata"]["port"] == 31337), None)
    assert backdoor_event is not None
    assert backdoor_event["severity"] == "HIGH"
    assert backdoor_event["metadata"]["mitre_technique"] == "T1571"

    # 3. Create SIEM Threat Alert in PostgreSQL
    rootkit_alert = Alert(
        tenant_id=test_tenant.id,
        rule_code="ROOTKIT_BACKDOOR_DETECTED",
        severity=SeverityEnum.CRITICAL,
        host=agent_id,
        source_ip="198.51.100.99",
        destination_ip="192.168.1.150",
        reason="Rootcheck anomaly: Kernel rootkit artifact detected and unmapped listener on port 31337",
        mitre_technique_id="T1014",
        status=AlertStatusEnum.NEW,
    )
    db_session.add(rootkit_alert)
    await db_session.commit()
    await db_session.refresh(rootkit_alert)

    # 4. Automated Alert Active Response Dispatch
    auto_task = await ActiveResponseService.dispatch_alert_response(
        db=db_session,
        alert=rootkit_alert,
    )
    assert auto_task is not None
    assert auto_task.status == ActiveResponseTaskStatusEnum.PENDING
    assert auto_task.action == ActiveResponseActionEnum.BLOCK_IP

    # 5. Trigger File Quarantine Active Response Task
    quarantine_req = ActiveResponseTriggerRequest(
        agent_id=agent_id,
        action=ActiveResponseActionEnum.QUARANTINE_FILE,
        target=str(sample_rootkit),
        parameters={"reason": "Isolate diamorphine rootkit kernel module"},
        alert_id=rootkit_alert.id,
    )
    q_resp = await client.post(
        "/api/v1/active_response/trigger",
        json=quarantine_req.model_dump(),
        headers=auth_headers,
    )
    assert q_resp.status_code == 201
    quarantine_task_id = q_resp.json()["id"]

    # 6. Agent polls pending tasks
    poll_resp = await client.get(
        f"/api/v1/active_response/agents/{agent_id}/pending",
        headers=auth_headers,
    )
    assert poll_resp.status_code == 200
    pending_tasks = poll_resp.json()
    assert any(t["id"] == quarantine_task_id for t in pending_tasks)

    # 7. Agent executes ActiveResponseExecutor with genuine file quarantine vault
    executor = ActiveResponseExecutor(
        agent_id=agent_id,
        tenant_id=test_tenant.id,
        quarantine_dir=quarantine_vault,
        dry_run=False,
    )

    quarantine_result = executor.quarantine_file(sample_rootkit)
    assert quarantine_result["status"] == "SUCCESS"
    sha256 = quarantine_result["sha256"]
    assert sha256 is not None

    # Verify original file removed from filesystem
    assert not sample_rootkit.exists()

    # Verify quarantined payload and manifest JSON exist in secure vault
    vault_artifact = quarantine_vault / f"{sha256}.quarantine"
    vault_manifest = quarantine_vault / f"{sha256}.manifest.json"
    assert vault_artifact.exists()
    assert vault_manifest.exists()

    # 8. Agent submits execution callback
    cb_update = ActiveResponseStatusUpdate(
        task_id=quarantine_task_id,
        status=ActiveResponseTaskStatusEnum.SUCCESS,
        stdout=f"Rootkit artifact quarantined to vault with SHA256={sha256}",
    )
    cb_resp = await client.post(
        f"/api/v1/active_response/tasks/{quarantine_task_id}/result",
        json=cb_update.model_dump(),
        headers=auth_headers,
    )
    assert cb_resp.status_code == 200
    assert cb_resp.json()["status"] == "SUCCESS"

    # 9. Verify unquarantine capability restores file intact
    restore_result = executor.unquarantine_file(sha256)
    assert restore_result["status"] == "SUCCESS"
    assert sample_rootkit.exists()
    assert sample_rootkit.read_bytes() == b"\x7fELF_ROOTKIT_PAYLOAD_DIAMORPHINE_31337"


@pytest.mark.asyncio
async def test_scenario_cis_drift_and_sudo_privesc(
    client: AsyncClient,
    db_session: AsyncSession,
    test_tenant: Tenant,
    test_user: User,
    auth_headers: dict[str, str],
):
    """
    Scenario 3: CIS Benchmark Drift & Baron Samedit Privilege Escalation (CVE-2021-3156).
    Workflow:
    - Baseline SCA report is ingested with 100.0% compliance.
    - Configuration drift occurs (SSH root login enabled, weak password policy) -> compliance drops to 80.0%.
    - Vulnerability Engine audits package inventory and flags Sudo 1.8.31 vulnerable to Baron Samedit (CVE-2021-3156).
    - Security Incident is created and assigned to analyst for investigation.
    - Analyst updates incident status (OPEN -> INVESTIGATING -> RESOLVED) with remediation notes.
    - AuditLog records all incident lifecycle mutations.
    """
    agent_id = "agent-sca-drift01"

    # 1. Enroll agent
    agent = Agent(
        id=agent_id,
        tenant_id=test_tenant.id,
        hostname="srv-worker-01",
        ip_address="10.0.5.20",
        os_type="linux",
        os_version="Ubuntu 22.04 LTS",
        status=AgentStatusEnum.ONLINE,
    )
    db_session.add(agent)
    await db_session.commit()

    # 2. Baseline SCA Scan (10 passed -> 100.0% compliance)
    baseline_payload = {
        "policy_id": "cis_ubuntu_2204",
        "policy_name": "CIS Ubuntu Linux 22.04 Benchmark",
        "agent_id": agent_id,
        "tenant_id": test_tenant.id,
        "total_checks": 10,
        "passed_checks": 10,
        "failed_checks": 0,
        "not_applicable_checks": 0,
        "compliance_score": 100.0,
        "checks": [
            {"id": f"CIS-1.{i}", "title": f"Security Baseline Control {i}", "status": "PASS", "remediation": ""}
            for i in range(1, 11)
        ],
    }
    base_resp = await client.post("/api/v1/sca/report", json=baseline_payload, headers=auth_headers)
    assert base_resp.status_code == 201
    assert base_resp.json()["compliance_score"] == 100.0

    # 3. Configuration Drift Scan (2 checks drift to FAIL -> compliance drops to 80.0%)
    drift_payload = {
        "policy_id": "cis_ubuntu_2204",
        "policy_name": "CIS Ubuntu Linux 22.04 Benchmark",
        "agent_id": agent_id,
        "tenant_id": test_tenant.id,
        "total_checks": 10,
        "passed_checks": 8,
        "failed_checks": 2,
        "not_applicable_checks": 0,
        "checks": [
            {"id": "CIS-LNX-2.1.1", "title": "Disable SSH Root Login", "status": "FAIL", "remediation": "Set PermitRootLogin no in /etc/ssh/sshd_config"},
            {"id": "CIS-LNX-5.1.1", "title": "Ensure Password Expiration <= 90 Days", "status": "FAIL", "remediation": "Set PASS_MAX_DAYS 90 in /etc/login.defs"},
        ] + [
            {"id": f"CIS-1.{i}", "title": f"Security Control {i}", "status": "PASS", "remediation": ""}
            for i in range(3, 11)
        ],
    }
    drift_resp = await client.post("/api/v1/sca/report", json=drift_payload, headers=auth_headers)
    assert drift_resp.status_code == 201
    assert drift_resp.json()["compliance_score"] == 80.0

    # Verify summary API reflects compliance drift
    summary_resp = await client.get("/api/v1/sca/summary", headers=auth_headers)
    assert summary_resp.status_code == 200
    summary_data = summary_resp.json()
    assert summary_data["total_scans"] == 2
    assert summary_data["average_compliance_score"] == 90.0

    # 4. Vulnerability Engine detects Baron Samedit (CVE-2021-3156) in sudo 1.8.31
    vuln_scan_payload = VulnerabilityScanPayload(
        agent_id=agent_id,
        tenant_id=test_tenant.id,
        packages=[
            {"name": "sudo", "version": "1.8.31"},
            {"name": "bash", "version": "5.1.16"},
        ],
    )
    vuln_resp = await client.post(
        "/api/v1/vulnerabilities/scan",
        json=vuln_scan_payload.model_dump(),
        headers=auth_headers,
    )
    assert vuln_resp.status_code == 200
    vuln_data = vuln_resp.json()
    assert vuln_data["vulnerability_count"] >= 1

    # Verify Baron Samedit finding in database
    sudo_finding_query = await db_session.execute(
        select(VulnerabilityFinding).where(
            VulnerabilityFinding.agent_id == agent_id,
            VulnerabilityFinding.cve_id == "CVE-2021-3156",
        )
    )
    sudo_finding = sudo_finding_query.scalar_one()
    assert sudo_finding.severity == SeverityEnum.HIGH
    assert sudo_finding.cvss_score == 7.8

    # 5. Security Analyst creates and triages Security Incident
    incident_create_req = IncidentCreate(
        title="Privilege Escalation Risk: CIS Drift & Baron Samedit CVE-2021-3156",
        description=(
            f"Host {agent_id} experienced CIS benchmark compliance drift to 80% with SSH root login enabled, "
            f"and installed sudo package 1.8.31 is vulnerable to Baron Samedit (CVE-2021-3156) local privilege escalation."
        ),
        severity=SeverityEnum.HIGH,
        assigned_analyst_id=test_user.id,
    )
    inc_resp = await client.post(
        "/api/v1/incidents",
        json=incident_create_req.model_dump(),
        headers=auth_headers,
    )
    assert inc_resp.status_code == 201
    incident_data = inc_resp.json()
    incident_id = incident_data["id"]
    assert incident_data["status"] == "OPEN"
    assert incident_data["assigned_analyst_id"] == test_user.id

    # 6. Analyst updates status to INVESTIGATING
    update_inv = IncidentUpdateStatus(
        status=IncidentStatusEnum.INVESTIGATING,
        note="Deploying sudo 1.9.5p3 package upgrade and enforcing SSH root login restriction via Ansible playbook.",
    )
    inv_resp = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json=update_inv.model_dump(),
        headers=auth_headers,
    )
    assert inv_resp.status_code == 200
    assert inv_resp.json()["status"] == "INVESTIGATING"

    # 7. Analyst resolves Incident
    update_res = IncidentUpdateStatus(
        status=IncidentStatusEnum.RESOLVED,
        note="Remediation verified: Sudo patched to 1.9.5p3 and CIS compliance restored to 100%.",
    )
    res_resp = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json=update_res.model_dump(),
        headers=auth_headers,
    )
    assert res_resp.status_code == 200
    resolved_inc = res_resp.json()
    assert resolved_inc["status"] == "RESOLVED"
    assert len(resolved_inc["notes"]) == 2

    # 8. Verify AuditLog tracks incident lifecycle
    audit_query = await db_session.execute(
        select(AuditLog).where(
            AuditLog.tenant_id == test_tenant.id,
            AuditLog.resource_type == "Incident",
            AuditLog.resource_id == incident_id,
        )
    )
    incident_audits = audit_query.scalars().all()
    assert len(incident_audits) >= 3  # Create + 2 status updates
    assert any(a.action == "CREATE_INCIDENT" for a in incident_audits)
    assert any(a.action == "UPDATE_INCIDENT_STATUS" for a in incident_audits)


@pytest.mark.asyncio
async def test_scenario_brute_force_login_containment(
    client: AsyncClient,
    db_session: AsyncSession,
    test_tenant: Tenant,
    test_user: User,
    auth_headers: dict[str, str],
):
    """
    Scenario 4: High-Volume Endpoint Brute Force Attack.
    Workflow:
    - High-volume batch of failed authentication events (Event Code 4625) from brute-force IP (198.51.100.77).
    - Event Ingestion Gateway accepts batch, streams to Kafka, indexes into OpenSearch, and feeds DetectionEngine.
    - Detection rule `BRUTE_FORCE_LOGIN` triggers upon threshold crossing (5 failed attempts within 300s window).
    - High-severity Alert is created in database.
    - Automated Active Response evaluates alert and dispatches automated IP block containment task.
    - Agent polls pending task, executes containment via ActiveResponseExecutor, and returns SUCCESS.
    - OpenSearch event explorer verifies all events are indexed and queryable.
    """
    agent_id = "agent-dc-win01"
    attacker_ip = "198.51.100.77"
    target_user = "Administrator"
    now = datetime.now(UTC)

    # 1. Enroll agent
    agent = Agent(
        id=agent_id,
        tenant_id=test_tenant.id,
        hostname="DC01.corp.internal",
        ip_address="192.168.10.10",
        os_type="windows",
        os_version="Windows Server 2022",
        status=AgentStatusEnum.ONLINE,
    )
    db_session.add(agent)
    await db_session.commit()

    # 2. Generate 6 rapid failed authentication events (Windows Event 4625)
    brute_force_events = []
    for i in range(6):
        brute_force_events.append(
            {
                "event_id": f"brute-evt-{uuid.uuid4()}",
                "tenant_id": test_tenant.id,
                "agent_id": agent_id,
                "timestamp": now.isoformat(),
                "source_type": "windows_event_log",
                "host": agent_id,
                "source_ip": attacker_ip,
                "user": target_user,
                "event_type": "authentication",
                "action": "logon_failed",
                "severity": "HIGH",
                "message": f"An account failed to log on. Subject: {target_user}, Status: 0xC000006D, EventCode: 4625 (Attempt {i+1})",
                "process": "C:\\Windows\\System32\\lsass.exe",
                "metadata": {"event_code": 4625, "failure_reason": "Unknown user name or bad password"},
            }
        )

    # Ingest batch via Ingestion Gateway
    ingest_resp = await client.post(
        "/api/v1/events/ingest",
        json={"events": brute_force_events},
    )
    assert ingest_resp.status_code == 202
    assert ingest_resp.json()["accepted"] == 6

    # 3. Evaluate Rule via DetectionEngine directly and generate alert
    detection_engine = DetectionEngine(rules_dir="detection-rules")
    fired_alert: Alert | None = None
    for evt in brute_force_events:
        alert = detection_engine.evaluate_event(evt)
        if alert:
            fired_alert = alert

    assert fired_alert is not None
    assert fired_alert.rule_code == "BRUTE_FORCE_LOGIN"
    assert fired_alert.severity == SeverityEnum.HIGH
    assert fired_alert.source_ip == attacker_ip
    assert fired_alert.mitre_technique_id == "T1110"

    # Persist alert in database
    db_session.add(fired_alert)
    await db_session.commit()
    await db_session.refresh(fired_alert)

    # 4. Automated Active Response Containment Dispatch
    task = await ActiveResponseService.dispatch_alert_response(
        db=db_session,
        alert=fired_alert,
    )
    assert task is not None
    assert task.status == ActiveResponseTaskStatusEnum.PENDING
    assert task.action == ActiveResponseActionEnum.BLOCK_IP
    assert task.target == attacker_ip
    task_id = task.id

    # 5. Agent polls pending containment tasks
    poll_resp = await client.get(
        f"/api/v1/active_response/agents/{agent_id}/pending",
        headers=auth_headers,
    )
    assert poll_resp.status_code == 200
    pending_tasks = poll_resp.json()
    assert any(t["id"] == task_id for t in pending_tasks)

    # 6. Agent executes ActiveResponseExecutor
    executor = ActiveResponseExecutor(
        agent_id=agent_id,
        tenant_id=test_tenant.id,
        dry_run=True,
    )
    exec_result = executor.block_ip(attacker_ip, duration_seconds=1800)
    assert exec_result["status"] == "SUCCESS"

    # 7. Agent submits callback result
    update = ActiveResponseStatusUpdate(
        task_id=task_id,
        status=ActiveResponseTaskStatusEnum.SUCCESS,
        exit_code=0,
        stdout=f"Automated firewall block rule added for brute force IP {attacker_ip}",
    )
    cb_resp = await client.post(
        f"/api/v1/active_response/tasks/{task_id}/result",
        json=update.model_dump(),
        headers=auth_headers,
    )
    assert cb_resp.status_code == 200
    assert cb_resp.json()["status"] == "SUCCESS"

    # 8. Query OpenSearch event explorer via API
    events_query_resp = await client.get(
        f"/api/v1/events?event_type=authentication&search={attacker_ip}",
        headers=auth_headers,
    )
    assert events_query_resp.status_code == 200
    retrieved_events = events_query_resp.json()
    assert len(retrieved_events) >= 6
    assert all(e["source_ip"] == attacker_ip for e in retrieved_events)


@pytest.mark.asyncio
async def test_scenario_agent_offline_buffering_and_resync(
    client: AsyncClient,
    test_tenant: Tenant,
    test_user: User,
    auth_headers: dict[str, str],
    tmp_path: Path,
):
    """
    Scenario 5: Agent Offline Buffering & Resilient Re-synchronization.
    Workflow:
    - Agent experiences network disconnection from backend API.
    - Multiple collectors (Syscollector, SCA, Rootcheck) generate telemetry events during outage.
    - SQLiteQueue disk-backed FIFO queue buffers all events reliably without loss.
    - Queue persistence is validated across agent restarts.
    - Network connectivity is restored -> Agent flushes buffered batches to Ingestion Gateway.
    - Ingestion Gateway normalizes events into Kafka and indexes into OpenSearch with 100% data integrity.
    """
    agent_id = "agent-mobile-field01"
    db_queue_file = str(tmp_path / "offline_events.db")
    now = datetime.now(UTC)

    # 1. Initialize SQLiteQueue buffer
    queue = SQLiteQueue(db_path=db_queue_file)
    assert queue.size() == 0

    # 2. Generate telemetry from multiple collectors during network outage:
    buffered_events = []

    # A) Syscollector Inventory Event
    buffered_events.append(
        {
            "event_id": f"offline-syscol-{uuid.uuid4()}",
            "tenant_id": test_tenant.id,
            "agent_id": agent_id,
            "timestamp": now.isoformat(),
            "source_type": "syscollector",
            "host": "field-laptop-01",
            "event_type": "inventory_snapshot",
            "action": "snapshot_collected",
            "severity": "LOW",
            "message": "Syscollector hardware and software snapshot collected offline",
            "metadata": {"packages_count": 42, "cpu_cores": 4, "ram_gb": 16.0},
        }
    )

    # B) SCA Compliance Benchmark Events
    buffered_events.append(
        {
            "event_id": f"offline-sca-scan-{uuid.uuid4()}",
            "tenant_id": test_tenant.id,
            "agent_id": agent_id,
            "timestamp": now.isoformat(),
            "source_type": "sca",
            "host": "field-laptop-01",
            "event_type": "sca_compliance_scan",
            "action": "scan_completed",
            "severity": "LOW",
            "message": "SCA Compliance Audit completed offline with score 90.0%",
            "metadata": {"policy_id": "cis_linux_ubuntu_2204", "compliance_score": 90.0},
        }
    )
    buffered_events.append(
        {
            "event_id": f"offline-sca-find-{uuid.uuid4()}",
            "tenant_id": test_tenant.id,
            "agent_id": agent_id,
            "timestamp": now.isoformat(),
            "source_type": "sca",
            "host": "field-laptop-01",
            "event_type": "sca_compliance_finding",
            "action": "check_failed",
            "severity": "HIGH",
            "message": "SCA CIS Rule Failed: Disable SSH Root Login (CIS-LNX-2.1.1)",
            "metadata": {"check_id": "CIS-LNX-2.1.1", "title": "Disable SSH Root Login"},
        }
    )

    # C) Rootcheck Anomaly Events
    buffered_events.append(
        {
            "event_id": f"offline-rootcheck-file-{uuid.uuid4()}",
            "tenant_id": test_tenant.id,
            "agent_id": agent_id,
            "timestamp": now.isoformat(),
            "source_type": "rootcheck",
            "host": "field-laptop-01",
            "event_type": "rootkit_detection",
            "action": "suspicious_file_found",
            "severity": "CRITICAL",
            "message": "Rootcheck Alert: Anomalous SUID binary found in /tmp/privesc",
            "metadata": {"suspicious_path": "/tmp/privesc", "mitre_technique": "T1548.001"},
        }
    )
    buffered_events.append(
        {
            "event_id": f"offline-rootcheck-port-{uuid.uuid4()}",
            "tenant_id": test_tenant.id,
            "agent_id": agent_id,
            "timestamp": now.isoformat(),
            "source_type": "rootcheck",
            "host": "field-laptop-01",
            "event_type": "rootkit_detection",
            "action": "suspicious_port_listening",
            "severity": "HIGH",
            "message": "Rootcheck Alert: High-risk backdoor port 6667 detected listening",
            "metadata": {"port": 6667, "mitre_technique": "T1571"},
        }
    )

    # D) Additional process & command audit telemetry to create a 10-event batch
    for i in range(5):
        buffered_events.append(
            {
                "event_id": f"offline-telemetry-{i}-{uuid.uuid4()}",
                "tenant_id": test_tenant.id,
                "agent_id": agent_id,
                "timestamp": now.isoformat(),
                "source_type": "command_audit",
                "host": "field-laptop-01",
                "event_type": "process_execution",
                "action": "command_executed",
                "severity": "LOW",
                "message": f"Audit telemetry event {i}: User executed diagnostic command",
                "process": "/usr/bin/netstat",
                "metadata": {"command_index": i},
            }
        )

    # 3. Buffer all 10 events into SQLiteQueue during outage
    for evt in buffered_events:
        queue.push(evt)

    assert queue.size() == 10

    # 4. Validate persistence across queue re-initialization (agent restart)
    reopened_queue = SQLiteQueue(db_path=db_queue_file)
    assert reopened_queue.size() == 10

    # 5. Network Restored: Pop batch and flush to backend Ingestion Gateway
    popped_batch = reopened_queue.pop_batch(batch_size=50)
    assert len(popped_batch) == 10

    ingest_resp = await client.post(
        "/api/v1/events/ingest",
        json={"events": popped_batch},
    )
    assert ingest_resp.status_code == 202
    ingest_data = ingest_resp.json()
    assert ingest_data["accepted"] == 10
    assert ingest_data["failed"] == 0

    # Acknowledge and clear popped batch from SQLiteQueue
    reopened_queue.delete_batch(batch_size=50)
    assert reopened_queue.size() == 0

    # 6. Verify Kafka streaming queues received the flushed events
    raw_kafka_msgs = kafka_producer.get_topic_messages("arka.events.raw")
    assert any(m["event_id"] == popped_batch[0]["event_id"] for m in raw_kafka_msgs)

    # 7. Query OpenSearch event explorer via API for all 3 collector source types
    # Syscollector event
    resp_syscol = await client.get("/api/v1/events?search=Syscollector", headers=auth_headers)
    assert resp_syscol.status_code == 200
    assert len(resp_syscol.json()) >= 1

    # SCA event
    resp_sca = await client.get("/api/v1/events?event_type=sca_compliance_scan", headers=auth_headers)
    assert resp_sca.status_code == 200
    assert len(resp_sca.json()) >= 1

    # Rootcheck events
    resp_rootcheck = await client.get("/api/v1/events?event_type=rootkit_detection", headers=auth_headers)
    assert resp_rootcheck.status_code == 200
    assert len(resp_rootcheck.json()) >= 2
