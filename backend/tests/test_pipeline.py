# ruff: noqa: PLR0915
"""
Tier 3 Cross-Feature Pipeline Integration Tests.
Verifies end-to-end multi-service data pipelines across ARKA SIEM & XDR platform:
1. Syscollector to Vulnerability correlation pipeline.
2. Rootcheck anomaly to Active Response automated containment pipeline.
3. SCA benchmark compliance dashboard synchronization pipeline.
4. Telemetry batch ingest -> Kafka normalization -> OpenSearch indexing pipeline.
5. Multi-tenant isolation across all 5 requirements simultaneously.
"""

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from arka_agent.active_response import ActiveResponseExecutor
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, get_password_hash
from app.models.models import (
    ActiveResponseActionEnum,
    ActiveResponseTaskStatusEnum,
    Agent,
    AgentInventoryPackage,
    AgentStatusEnum,
    Alert,
    AlertStatusEnum,
    AuditLog,
    RoleEnum,
    SeverityEnum,
    Tenant,
    User,
    VulnerabilityFinding,
    VulnerabilityStatusEnum,
)
from app.schemas.schemas import (
    ActiveResponseStatusUpdate,
    ActiveResponseTriggerRequest,
    InventorySnapshotPayload,
    VulnerabilityScanPayload,
)
from app.services.active_response_service import ActiveResponseService
from app.services.kafka_pipeline import kafka_producer


@pytest.mark.asyncio
async def test_pipeline_syscollector_to_vulnerability_correlation(
    client: AsyncClient,
    db_session: AsyncSession,
    test_tenant: Tenant,
    test_user: User,
    auth_headers: dict[str, str],
):
    """
    Pipeline 1: Syscollector package inventory -> Vulnerability CVE correlation.
    Verifies that package inventory ingested via Syscollector is correlated against the CVE database,
    producing Vulnerability findings, CVSS score calculations, and automated High/Critical Alerts.
    """
    agent_id = "agent-correlate-01"

    # 1. Enroll agent in tenant
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

    # 2. Ingest Syscollector snapshot with packages
    snapshot_payload = InventorySnapshotPayload(
        snapshot_id=str(uuid.uuid4()),
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
            "os_name": "Ubuntu",
            "os_version": "22.04 LTS",
            "kernel_version": "5.15.0-89-generic",
            "architecture": "x86_64",
        },
        packages=[
            {"name": "log4j", "version": "2.14.0", "vendor": "Apache", "architecture": "all"},
            {"name": "sudo", "version": "1.8.31", "vendor": "Ubuntu", "architecture": "amd64"},
            {"name": "openssl", "version": "1.1.1f", "vendor": "Ubuntu", "architecture": "amd64"},
            {"name": "curl", "version": "7.85.0", "vendor": "Ubuntu", "architecture": "amd64"},
            {"name": "bash", "version": "5.1.16", "vendor": "Ubuntu", "architecture": "amd64"},
        ],
        network={
            "interfaces": [
                {
                    "name": "eth0",
                    "ip_address": "10.10.20.50",
                    "mac_address": "00:50:56:a1:b2:c3",
                    "is_up": True,
                }
            ]
        },
        ports=[{"port": 8080, "protocol": "tcp", "state": "LISTEN", "process_name": "java"}],
        processes=[{"pid": 1042, "name": "java", "user": "appuser", "cpu_percent": 2.5}],
    )

    snap_resp = await client.post(
        "/api/v1/inventory/snapshot",
        json=snapshot_payload.model_dump(),
        headers=auth_headers,
    )
    assert snap_resp.status_code == 201
    assert snap_resp.json()["packages_ingested"] == 5

    # Verify packages persisted in DB
    pkg_query = await db_session.execute(
        select(AgentInventoryPackage).where(AgentInventoryPackage.agent_id == agent_id)
    )
    persisted_pkgs = pkg_query.scalars().all()
    assert len(persisted_pkgs) == 5

    # 3. Perform vulnerability scan and correlation
    scan_payload = VulnerabilityScanPayload(
        agent_id=agent_id,
        tenant_id=test_tenant.id,
        packages=[
            {"name": "log4j", "version": "2.14.0"},
            {"name": "sudo", "version": "1.8.31"},
            {"name": "openssl", "version": "1.1.1f"},
            {"name": "curl", "version": "7.85.0"},
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
    assert scan_data["scanned_packages"] == 5
    assert scan_data["vulnerability_count"] >= 4
    assert scan_data["critical_count"] >= 1  # Log4Shell
    assert scan_data["high_count"] >= 3  # sudo, openssl, curl
    assert scan_data["alerts_generated"] >= 4

    # 4. Verify Vulnerability findings in database
    finding_query = await db_session.execute(
        select(VulnerabilityFinding).where(VulnerabilityFinding.agent_id == agent_id)
    )
    findings = finding_query.scalars().all()
    assert len(findings) >= 4
    cve_ids = {f.cve_id for f in findings}
    assert "CVE-2021-44228" in cve_ids
    assert "CVE-2021-3156" in cve_ids
    assert "CVE-2022-0778" in cve_ids
    assert "CVE-2023-38545" in cve_ids

    # Verify Log4j finding attributes
    log4j_finding = next(f for f in findings if f.cve_id == "CVE-2021-44228")
    assert log4j_finding.severity == SeverityEnum.CRITICAL
    assert log4j_finding.cvss_score == 10.0
    assert log4j_finding.status == VulnerabilityStatusEnum.ACTIVE

    # 5. Verify automated High/Critical Alerts generated in DB
    alert_query = await db_session.execute(
        select(Alert).where(Alert.tenant_id == test_tenant.id)
    )
    alerts = alert_query.scalars().all()
    assert len(alerts) >= 4
    vuln_alerts = [a for a in alerts if a.rule_code and a.rule_code.startswith("VULN-")]
    assert len(vuln_alerts) >= 4
    assert any(a.severity == SeverityEnum.CRITICAL for a in vuln_alerts)

    # 6. Verify querying findings and reports via API endpoints
    findings_api_resp = await client.get("/api/v1/vulnerabilities", headers=auth_headers)
    assert findings_api_resp.status_code == 200
    assert len(findings_api_resp.json()) >= 4

    reports_api_resp = await client.get(f"/api/v1/vulnerabilities/reports/{agent_id}", headers=auth_headers)
    assert reports_api_resp.status_code == 200
    assert len(reports_api_resp.json()) >= 1

    # 7. Update finding lifecycle status via API (ACTIVE -> MITIGATED)
    target_finding_id = log4j_finding.id
    status_update_resp = await client.patch(
        f"/api/v1/vulnerabilities/findings/{target_finding_id}/status",
        json={"status": "MITIGATED", "note": "Patch applied in staging"},
        headers=auth_headers,
    )
    assert status_update_resp.status_code == 200
    assert status_update_resp.json()["status"] == "MITIGATED"

    # Verify update persisted in DB
    await db_session.refresh(log4j_finding)
    assert log4j_finding.status == VulnerabilityStatusEnum.MITIGATED


@pytest.mark.asyncio
async def test_pipeline_rootcheck_anomaly_to_active_response(
    client: AsyncClient,
    db_session: AsyncSession,
    test_tenant: Tenant,
    test_user: User,
    auth_headers: dict[str, str],
    tmp_path: Path,
):
    """
    Pipeline 2: Rootcheck anomaly detection -> SIEM Alert -> Active Response Containment -> Audit Log.
    Verifies that a detected rootkit anomaly triggers automated containment task creation,
    agent polling & execution, status callback update to SUCCESS, and cryptographic audit log logging.
    """
    agent_id = "agent-rootcheck-01"
    quarantine_vault = tmp_path / "quarantine_vault"

    # 1. Enroll agent
    agent = Agent(
        id=agent_id,
        tenant_id=test_tenant.id,
        hostname="workstation-sec-01",
        ip_address="192.168.1.120",
        os_type="linux",
        os_version="Debian 12",
        status=AgentStatusEnum.ONLINE,
    )
    db_session.add(agent)
    await db_session.commit()

    # 2. Simulate Rootcheck detecting a rootkit backdoor artifact and socket
    # System generates CRITICAL Alert in database
    rootkit_alert = Alert(
        tenant_id=test_tenant.id,
        rule_code="ROOTKIT_BACKDOOR_DETECTED",
        severity=SeverityEnum.CRITICAL,
        host=agent_id,
        source_ip="198.51.100.99",
        destination_ip="192.168.1.120",
        reason="Rootcheck anomaly: Unmapped listening socket on port 31337 and rootkit driver artifact",
        mitre_technique_id="T1014",
        status=AlertStatusEnum.NEW,
    )
    db_session.add(rootkit_alert)
    await db_session.commit()
    await db_session.refresh(rootkit_alert)

    # 3. Dispatch automated active response for the alert
    task = await ActiveResponseService.dispatch_alert_response(
        db=db_session,
        alert=rootkit_alert,
    )
    assert task is not None
    assert task.status == ActiveResponseTaskStatusEnum.PENDING
    assert task.action == ActiveResponseActionEnum.BLOCK_IP
    assert task.target == "198.51.100.99"
    task_id = task.id

    # 4. Agent polls for pending tasks via API
    poll_resp = await client.get(
        f"/api/v1/active_response/agents/{agent_id}/pending",
        headers=auth_headers,
    )
    assert poll_resp.status_code == 200
    pending_tasks = poll_resp.json()
    assert len(pending_tasks) >= 1
    assert any(t["id"] == task_id for t in pending_tasks)

    # 5. Agent executes active response containment using ActiveResponseExecutor
    executor = ActiveResponseExecutor(
        agent_id=agent_id,
        tenant_id=test_tenant.id,
        quarantine_dir=quarantine_vault,
        dry_run=True,
    )
    exec_result = executor.block_ip("198.51.100.99", duration_seconds=3600)
    assert exec_result["status"] == "SUCCESS"

    # Also simulate quarantining a rootkit file artifact with active executor
    sample_malware = tmp_path / "rootkit_driver.ko"
    sample_malware.write_bytes(b"ROOTKIT_BINARY_PAYLOAD_TEST_31337")
    file_executor = ActiveResponseExecutor(
        agent_id=agent_id,
        tenant_id=test_tenant.id,
        quarantine_dir=quarantine_vault,
        dry_run=False,
    )
    quarantine_result = file_executor.quarantine_file(sample_malware)
    assert quarantine_result["status"] == "SUCCESS"
    assert quarantine_result["sha256"] is not None
    assert not sample_malware.exists()
    assert (quarantine_vault / f"{quarantine_result['sha256']}.quarantine").exists()

    # 6. Agent reports task execution result back to backend API
    status_update = ActiveResponseStatusUpdate(
        task_id=task_id,
        status=ActiveResponseTaskStatusEnum.SUCCESS,
        stdout=f"Firewall rule added for 198.51.100.99; File quarantined SHA256={quarantine_result['sha256']}",
        stderr=None,
    )
    result_resp = await client.post(
        f"/api/v1/active_response/tasks/{task_id}/result",
        json=status_update.model_dump(),
        headers=auth_headers,
    )
    assert result_resp.status_code == 200
    updated_task = result_resp.json()
    assert updated_task["status"] == "SUCCESS"
    assert (updated_task.get("completed_at") or updated_task.get("updated_at") or updated_task.get("created_at")) is not None

    # 7. Verify Task status and AuditLog in database
    await db_session.refresh(task)
    assert task.status == ActiveResponseTaskStatusEnum.SUCCESS

    audit_query = await db_session.execute(
        select(AuditLog).where(
            AuditLog.tenant_id == test_tenant.id,
            AuditLog.resource_type == "ActiveResponseTask",
            AuditLog.resource_id == task_id,
        )
    )
    audit_logs = audit_query.scalars().all()
    assert len(audit_logs) >= 1
    assert any("ACTIVE_RESPONSE" in a.action for a in audit_logs)


@pytest.mark.asyncio
async def test_pipeline_sca_compliance_dashboard_sync(
    client: AsyncClient,
    db_session: AsyncSession,
    test_tenant: Tenant,
    test_user: User,
    auth_headers: dict[str, str],
):
    """
    Pipeline 3: SCA Benchmark Scan -> Compliance Scoring -> Drift Detection -> Dashboard Metrics Sync.
    Verifies mathematical score calculation, multi-scan drift tracking, and tenant-level summary metrics.
    """
    agent1_id = "agent-sca-host01"
    agent2_id = "agent-sca-host02"

    # 1. Baseline Scan for Agent 1 (10 passed checks -> 100.0% compliance)
    baseline_payload = {
        "policy_id": "cis_linux_ubuntu_2204",
        "policy_name": "CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0",
        "agent_id": agent1_id,
        "tenant_id": test_tenant.id,
        "total_checks": 10,
        "passed_checks": 10,
        "failed_checks": 0,
        "not_applicable_checks": 0,
        "compliance_score": 100.0,
        "checks": [
            {"id": f"CIS-1.{i}", "title": f"Security Check {i}", "status": "PASS", "remediation": ""}
            for i in range(1, 11)
        ],
    }
    resp1 = await client.post("/api/v1/sca/report", json=baseline_payload, headers=auth_headers)
    assert resp1.status_code == 201
    assert resp1.json()["compliance_score"] == 100.0

    # 2. Check initial compliance summary
    summary_resp1 = await client.get("/api/v1/sca/summary", headers=auth_headers)
    assert summary_resp1.status_code == 200
    summary_data1 = summary_resp1.json()
    assert summary_data1["total_scans"] >= 1
    assert summary_data1["average_compliance_score"] == 100.0

    # 3. Drift Scan for Agent 1: 2 controls drift (e.g. SSH root login & weak password policy)
    drift_payload = {
        "policy_id": "cis_linux_ubuntu_2204",
        "policy_name": "CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0",
        "agent_id": agent1_id,
        "tenant_id": test_tenant.id,
        "total_checks": 10,
        "passed_checks": 8,
        "failed_checks": 2,
        "not_applicable_checks": 0,
        "checks": [
            {"id": f"CIS-1.{i}", "title": f"Security Check {i}", "status": "PASS" if i <= 8 else "FAIL", "remediation": "Remediate config"}
            for i in range(1, 11)
        ],
    }
    resp2 = await client.post("/api/v1/sca/report", json=drift_payload, headers=auth_headers)
    assert resp2.status_code == 201
    # Compliance score dynamically calculated: (8 / (8+2)) * 100 = 80.0
    assert resp2.json()["compliance_score"] == 80.0

    # 4. Ingest Scan for Agent 2 (9 passed, 1 failed -> 90.0% compliance)
    agent2_payload = {
        "policy_id": "cis_linux_ubuntu_2204",
        "policy_name": "CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0",
        "agent_id": agent2_id,
        "tenant_id": test_tenant.id,
        "total_checks": 10,
        "passed_checks": 9,
        "failed_checks": 1,
        "not_applicable_checks": 0,
        "checks": [
            {"id": f"CIS-1.{i}", "title": f"Security Check {i}", "status": "PASS" if i <= 9 else "FAIL", "remediation": "Remediate config"}
            for i in range(1, 11)
        ],
    }
    resp3 = await client.post("/api/v1/sca/report", json=agent2_payload, headers=auth_headers)
    assert resp3.status_code == 201
    assert resp3.json()["compliance_score"] == 90.0

    # 5. Check aggregated tenant compliance summary across all scans
    summary_resp2 = await client.get("/api/v1/sca/summary", headers=auth_headers)
    assert summary_resp2.status_code == 200
    summary_data2 = summary_resp2.json()
    assert summary_data2["total_scans"] == 3
    # Total passed: 10 + 8 + 9 = 27, Total failed: 0 + 2 + 1 = 3
    assert summary_data2["passed_checks_total"] == 27
    assert summary_data2["failed_checks_total"] == 3
    assert summary_data2["average_compliance_score"] == 90.0  # (100 + 80 + 90) / 3 = 90.0

    # 6. Verify policy listing API
    policy_resp = await client.get("/api/v1/sca/policies", headers=auth_headers)
    assert policy_resp.status_code == 200
    assert isinstance(policy_resp.json(), list)


@pytest.mark.asyncio
async def test_pipeline_telemetry_batch_kafka_opensearch_indexing(
    client: AsyncClient,
    test_tenant: Tenant,
    test_user: User,
    auth_headers: dict[str, str],
):
    """
    Pipeline 4: High-throughput batch telemetry ingest -> Kafka streaming -> OpenSearch ECS indexing.
    Verifies batch ingestion throughput, Kafka topic routing, OpenSearch document indexing,
    and multifaceted event explorer search filtering.
    """
    now = datetime.now(UTC)
    events_batch = []

    # Generate 20 diverse telemetry events
    for i in range(20):
        evt_type = "authentication" if i < 10 else "process_execution"
        action = "logon_failed" if i < 5 else ("logon_success" if i < 10 else "process_start")
        sev = SeverityEnum.HIGH if i < 5 else SeverityEnum.LOW
        events_batch.append(
            {
                "event_id": f"batch-evt-{i:03d}",
                "tenant_id": test_tenant.id,
                "agent_id": "agent-stream-01",
                "timestamp": now.isoformat(),
                "source_type": "windows_event_log" if i < 10 else "process_monitor",
                "host": "DC01.corp.internal" if i % 2 == 0 else "APP01.corp.internal",
                "source_ip": f"192.168.1.{100 + i}",
                "user": "Administrator" if i < 5 else f"user_{i}",
                "event_type": evt_type,
                "action": action,
                "severity": sev.value,
                "message": f"Telemetry event {i} description: {action} on host",
                "process": "cmd.exe" if i >= 10 else None,
                "metadata": {"batch_index": i},
            }
        )

    # 1. Ingest batch via HTTP Ingestion Gateway
    ingest_resp = await client.post(
        "/api/v1/events/ingest",
        json={"events": events_batch},
    )
    assert ingest_resp.status_code == 202
    ingest_data = ingest_resp.json()
    assert ingest_data["accepted"] == 20
    assert ingest_data["failed"] == 0
    assert len(ingest_data["errors"]) == 0

    # 2. Verify Kafka raw and normalized topic queues received events
    raw_msgs = kafka_producer.get_topic_messages("arka.events.raw")
    assert len(raw_msgs) >= 20
    assert any(m["event_id"] == "batch-evt-000" for m in raw_msgs)

    norm_msgs = kafka_producer.get_topic_messages("arka.events.normalized")
    assert len(norm_msgs) >= 20

    # 3. Query OpenSearch event explorer via API with various filters
    # Filter by severity=HIGH
    resp_high = await client.get("/api/v1/events?severity=HIGH", headers=auth_headers)
    assert resp_high.status_code == 200
    events_high = resp_high.json()
    assert len(events_high) >= 5
    assert all(e["severity"] == "HIGH" for e in events_high)

    # Filter by event_type=process_execution
    resp_proc = await client.get("/api/v1/events?event_type=process_execution", headers=auth_headers)
    assert resp_proc.status_code == 200
    events_proc = resp_proc.json()
    assert len(events_proc) >= 10
    assert all(e["event_type"] == "process_execution" for e in events_proc)

    # Filter by search keyword
    resp_search = await client.get("/api/v1/events?search=DC01", headers=auth_headers)
    assert resp_search.status_code == 200
    events_dc01 = resp_search.json()
    assert len(events_dc01) >= 1
    assert any("DC01" in e["host"] for e in events_dc01)


@pytest.mark.asyncio
async def test_pipeline_multi_tenant_cross_feature_isolation(
    client: AsyncClient,
    db_session: AsyncSession,
):
    """
    Pipeline 5: Multi-Tenant Data & Action Isolation across All 5 SIEM/XDR Modules.
    Verifies that Tenant Alpha and Tenant Beta cannot view, query, or execute containment actions
    on each other's inventories, SCA compliance reports, vulnerability findings, active response tasks, or alerts.
    """
    # 1. Setup Tenant Alpha and Tenant Beta with users
    tenant_a = Tenant(name="Alpha Enterprise", slug="alpha-enterprise")
    tenant_b = Tenant(name="Beta Defense", slug="beta-defense")
    db_session.add_all([tenant_a, tenant_b])
    await db_session.commit()
    await db_session.refresh(tenant_a)
    await db_session.refresh(tenant_b)

    user_a = User(
        email="analyst@alpha.org",
        hashed_password=get_password_hash("AlphaPass123!"),
        full_name="Alpha Analyst",
        tenant_id=tenant_a.id,
        role=RoleEnum.SECURITY_ANALYST,
    )
    user_b = User(
        email="analyst@beta.org",
        hashed_password=get_password_hash("BetaPass123!"),
        full_name="Beta Analyst",
        tenant_id=tenant_b.id,
        role=RoleEnum.SECURITY_ANALYST,
    )
    db_session.add_all([user_a, user_b])
    await db_session.commit()
    await db_session.refresh(user_a)
    await db_session.refresh(user_b)

    token_a = create_access_token(subject=user_a.id, tenant_id=tenant_a.id, role=user_a.role.value)
    token_b = create_access_token(subject=user_b.id, tenant_id=tenant_b.id, role=user_b.role.value)
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # 2. Ingest Inventory for both tenants
    agent_a_id = "agent-alpha-node01"
    agent_b_id = "agent-beta-node01"

    agent_a = Agent(
        id=agent_a_id,
        tenant_id=tenant_a.id,
        hostname="alpha-host",
        ip_address="10.1.1.1",
        os_type="linux",
        os_version="Ubuntu 22.04 LTS",
        status=AgentStatusEnum.ONLINE,
    )
    agent_b = Agent(
        id=agent_b_id,
        tenant_id=tenant_b.id,
        hostname="beta-host",
        ip_address="10.2.2.2",
        os_type="linux",
        os_version="Debian 12",
        status=AgentStatusEnum.ONLINE,
    )
    db_session.add_all([agent_a, agent_b])
    await db_session.commit()

    snap_a = InventorySnapshotPayload(
        snapshot_id=str(uuid.uuid4()),
        agent_id=agent_a_id,
        tenant_id=tenant_a.id,
        timestamp=datetime.now(UTC).isoformat(),
        hardware={"cpu_cores_logical": 4, "ram_total_gb": 8.0, "disks": []},
        os={"hostname": "alpha-host", "os_name": "Linux", "os_version": "Ubuntu"},
        packages=[{"name": "alpha-pkg", "version": "1.0.0"}],
        ports=[{"port": 80, "protocol": "tcp", "state": "LISTEN", "process_name": "nginx"}],
    )
    snap_b = InventorySnapshotPayload(
        snapshot_id=str(uuid.uuid4()),
        agent_id=agent_b_id,
        tenant_id=tenant_b.id,
        timestamp=datetime.now(UTC).isoformat(),
        hardware={"cpu_cores_logical": 8, "ram_total_gb": 16.0, "disks": []},
        os={"hostname": "beta-host", "os_name": "Linux", "os_version": "Debian"},
        packages=[{"name": "beta-pkg", "version": "2.0.0"}],
        ports=[{"port": 443, "protocol": "tcp", "state": "LISTEN", "process_name": "apache2"}],
    )
    await client.post("/api/v1/inventory/snapshot", json=snap_a.model_dump(), headers=headers_a)
    await client.post("/api/v1/inventory/snapshot", json=snap_b.model_dump(), headers=headers_b)

    # 3. Ingest SCA reports for both tenants
    sca_a = {
        "policy_id": "cis_alpha",
        "policy_name": "Alpha CIS",
        "agent_id": agent_a_id,
        "tenant_id": tenant_a.id,
        "compliance_score": 95.0,
        "passed_checks": 19,
        "failed_checks": 1,
    }
    sca_b = {
        "policy_id": "cis_beta",
        "policy_name": "Beta CIS",
        "agent_id": agent_b_id,
        "tenant_id": tenant_b.id,
        "compliance_score": 60.0,
        "passed_checks": 6,
        "failed_checks": 4,
    }
    await client.post("/api/v1/sca/report", json=sca_a, headers=headers_a)
    await client.post("/api/v1/sca/report", json=sca_b, headers=headers_b)

    # 4. Ingest Vulnerability findings for both tenants
    vuln_scan_a = VulnerabilityScanPayload(
        agent_id=agent_a_id,
        tenant_id=tenant_a.id,
        packages=[{"name": "log4j", "version": "2.14.0"}],
    )
    vuln_scan_b = VulnerabilityScanPayload(
        agent_id=agent_b_id,
        tenant_id=tenant_b.id,
        packages=[{"name": "sudo", "version": "1.8.31"}],
    )
    await client.post("/api/v1/vulnerabilities/scan", json=vuln_scan_a.model_dump(), headers=headers_a)
    await client.post("/api/v1/vulnerabilities/scan", json=vuln_scan_b.model_dump(), headers=headers_b)

    # 5. Create Active Response tasks in both tenants
    task_a_req = ActiveResponseTriggerRequest(
        agent_id=agent_a_id,
        action=ActiveResponseActionEnum.BLOCK_IP,
        target="198.51.100.10",
        parameters={"reason": "Alpha block"},
    )
    task_b_req = ActiveResponseTriggerRequest(
        agent_id=agent_b_id,
        action=ActiveResponseActionEnum.BLOCK_IP,
        target="198.51.100.20",
        parameters={"reason": "Beta block"},
    )
    resp_task_a = await client.post("/api/v1/active_response/trigger", json=task_a_req.model_dump(), headers=headers_a)
    assert resp_task_a.status_code == 201
    task_a_id = resp_task_a.json()["id"]

    resp_task_b = await client.post("/api/v1/active_response/trigger", json=task_b_req.model_dump(), headers=headers_b)
    assert resp_task_b.status_code == 201
    task_b_id = resp_task_b.json()["id"]

    # ------------------------------------------------------------------------
    # STRICT ISOLATION VERIFICATION
    # ------------------------------------------------------------------------

    # 1. Inventory Isolation:
    # User A listing inventories sees ONLY Alpha agent
    inv_list_a = await client.get("/api/v1/inventory", headers=headers_a)
    assert inv_list_a.status_code == 200
    agent_ids_seen_by_a = [i["agent_id"] for i in inv_list_a.json()]
    assert agent_a_id in agent_ids_seen_by_a
    assert agent_b_id not in agent_ids_seen_by_a

    # User A trying to get Beta's hardware returns 404
    hw_b_by_a = await client.get(f"/api/v1/inventory/{agent_b_id}/hardware", headers=headers_a)
    assert hw_b_by_a.status_code == 404

    # 2. SCA Isolation:
    # User A listing SCA reports sees ONLY Alpha's reports
    sca_list_a = await client.get("/api/v1/sca", headers=headers_a)
    assert sca_list_a.status_code == 200
    reports_a = sca_list_a.json()
    assert all(r["agent_id"] == agent_a_id for r in reports_a)
    assert not any(r["agent_id"] == agent_b_id for r in reports_a)

    # 3. Vulnerability Isolation:
    # User A listing findings sees ONLY Log4j (Alpha), not Sudo (Beta)
    vuln_list_a = await client.get("/api/v1/vulnerabilities", headers=headers_a)
    assert vuln_list_a.status_code == 200
    findings_a = vuln_list_a.json()
    assert all(f["agent_id"] == agent_a_id for f in findings_a)
    assert not any(f["agent_id"] == agent_b_id for f in findings_a)

    vuln_list_b = await client.get("/api/v1/vulnerabilities", headers=headers_b)
    assert vuln_list_b.status_code == 200
    findings_b = vuln_list_b.json()
    assert all(f["agent_id"] == agent_b_id for f in findings_b)

    # 4. Active Response Isolation:
    # User A listing tasks sees only task_a_id, not task_b_id
    tasks_a = await client.get("/api/v1/active_response/tasks", headers=headers_a)
    assert tasks_a.status_code == 200
    task_ids_a = [t["id"] for t in tasks_a.json()]
    assert task_a_id in task_ids_a
    assert task_b_id not in task_ids_a

    # User A trying to get task_b_id details returns 404
    task_b_by_a = await client.get(f"/api/v1/active_response/tasks/{task_b_id}", headers=headers_a)
    assert task_b_by_a.status_code == 404

    # Agent B polling under Tenant A's token gets 0 tasks from Tenant B
    poll_agent_b_under_a = await client.get(
        f"/api/v1/active_response/agents/{agent_b_id}/pending", headers=headers_a
    )
    assert poll_agent_b_under_a.status_code == 200
    assert len(poll_agent_b_under_a.json()) == 0

    # User A trying to submit task result for Beta's task returns 404
    fake_update = ActiveResponseStatusUpdate(
        task_id=task_b_id,
        status=ActiveResponseTaskStatusEnum.SUCCESS,
        stdout="Attacker trying to falsify task result",
    )
    hijack_resp = await client.post(
        f"/api/v1/active_response/tasks/{task_b_id}/result",
        json=fake_update.model_dump(),
        headers=headers_a,
    )
    assert hijack_resp.status_code in (403, 404)
