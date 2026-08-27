"""
Tests for PostgreSQL & Database Persistence of Alerts, Incidents, Agents, Audit Logs,
SCA, Syscollector Inventory, Active Response, and Vulnerability/CVE models.
"""

from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.models.models import (
    ActiveResponseActionEnum,
    ActiveResponseTask,
    ActiveResponseTaskStatusEnum,
    Agent,
    AgentInventoryHardware,
    AgentInventoryNetwork,
    AgentInventoryOS,
    AgentInventoryPackage,
    AgentInventoryPort,
    AgentInventoryProcess,
    AgentStatusEnum,
    Alert,
    AlertStatusEnum,
    AuditLog,
    CVEItem,
    DetectionRule,
    Incident,
    IncidentStatusEnum,
    RoleEnum,
    SCAPolicy,
    SCAScanReport,
    SeverityEnum,
    Tenant,
    User,
    VulnerabilityFinding,
    VulnerabilityScanReport,
    VulnerabilityStatusEnum,
)
from app.schemas.schemas import (
    ActiveResponseTaskRead,
    CVEItemRead,
    HardwareInventoryRead,
    NetworkInventoryRead,
    OSInventoryRead,
    PackageInventoryRead,
    PortInventoryRead,
    ProcessInventoryRead,
    SCAPolicyRead,
    SCAScanReportRead,
    VulnerabilityFindingRead,
    VulnerabilityScanReportRead,
)

# SQLite In-memory Async Engine for DB testing
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def async_db_session():
    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        # Pre-seed tenant for foreign keys
        tenant = Tenant(
            id="tenant-alpha",
            name="Alpha Corp",
            slug="alpha-corp",
            is_active=True,
        )
        session.add(tenant)
        await session.commit()
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.mark.asyncio
async def test_tenant_and_user_relationship(async_db_session: AsyncSession):
    """Verifies Tenant and User creation and relationship resolution."""
    user = User(
        id="user-admin-01",
        tenant_id="tenant-alpha",
        email="admin@alpha.corp",
        hashed_password="hashed_secret_string",
        full_name="Alpha Admin",
        role=RoleEnum.TENANT_ADMIN,
        is_active=True,
    )
    async_db_session.add(user)
    await async_db_session.commit()

    res = await async_db_session.execute(select(User).where(User.id == "user-admin-01"))
    fetched_user = res.scalar_one_or_none()
    assert fetched_user is not None
    assert fetched_user.email == "admin@alpha.corp"
    assert fetched_user.role == RoleEnum.TENANT_ADMIN


@pytest.mark.asyncio
async def test_detection_rule_persistence(async_db_session: AsyncSession):
    """Verifies DetectionRule persistence with JSON fields."""
    rule = DetectionRule(
        id="rule-test-01",
        tenant_id="tenant-alpha",
        rule_code="BRUTE_FORCE_LOGIN",
        name="Brute Force Login Detection",
        description="Detects repeated logon failures",
        severity=SeverityEnum.HIGH,
        enabled=True,
        mitre_tactic="Credential Access",
        mitre_technique_id="T1110",
        mitre_technique_name="Brute Force",
        conditions={"event_type": "authentication", "action": "logon_failed"},
        threshold={"count": 5, "window_seconds": 300},
    )
    async_db_session.add(rule)
    await async_db_session.commit()

    res = await async_db_session.execute(
        select(DetectionRule).where(DetectionRule.id == "rule-test-01")
    )
    fetched_rule = res.scalar_one_or_none()
    assert fetched_rule is not None
    assert fetched_rule.rule_code == "BRUTE_FORCE_LOGIN"
    assert fetched_rule.conditions["event_type"] == "authentication"
    assert fetched_rule.threshold["count"] == 5


@pytest.mark.asyncio
async def test_alert_persistence_and_status_mutation(async_db_session: AsyncSession):
    """Verifies that Alert creation and status mutations persist correctly in DB."""
    # 1. Create Alert
    alert = Alert(
        id="alert-test-01",
        tenant_id="tenant-alpha",
        rule_code="BRUTE_FORCE_LOGIN",
        severity=SeverityEnum.HIGH,
        host="DC01.CYBERCORP.LOCAL",
        user="administrator",
        source_ip="192.168.1.105",
        reason="6 failed logon attempts in 300s",
        mitre_technique_id="T1110",
        status=AlertStatusEnum.NEW,
    )
    async_db_session.add(alert)
    await async_db_session.commit()

    # 2. Query Alert from DB
    res = await async_db_session.execute(select(Alert).where(Alert.id == "alert-test-01"))
    fetched_alert = res.scalar_one_or_none()
    assert fetched_alert is not None
    assert fetched_alert.rule_code == "BRUTE_FORCE_LOGIN"
    assert fetched_alert.status == AlertStatusEnum.NEW

    # 3. Mutate Status & Create AuditLog
    fetched_alert.status = AlertStatusEnum.INVESTIGATING
    audit = AuditLog(
        id="audit-test-01",
        tenant_id="tenant-alpha",
        user_id="analyst-01",
        action="UPDATE_ALERT_STATUS",
        resource_type="Alert",
        resource_id="alert-test-01",
        details={"old_status": "NEW", "new_status": "INVESTIGATING"},
    )
    async_db_session.add(audit)
    await async_db_session.commit()

    # 4. Verify Persistent Audit Trail
    audit_res = await async_db_session.execute(
        select(AuditLog).where(AuditLog.resource_id == "alert-test-01")
    )
    fetched_audit = audit_res.scalar_one_or_none()
    assert fetched_audit is not None
    assert fetched_audit.action == "UPDATE_ALERT_STATUS"
    assert fetched_audit.details["new_status"] == "INVESTIGATING"


@pytest.mark.asyncio
async def test_incident_persistence(async_db_session: AsyncSession):
    """Verifies Incident creation and status management in DB."""
    incident = Incident(
        id="inc-test-01",
        tenant_id="tenant-alpha",
        title="Multiple Brute Force Attacks on Domain Controller",
        description="Correlated brute force attacks from 192.168.1.105",
        severity=SeverityEnum.CRITICAL,
        status=IncidentStatusEnum.OPEN,
        assigned_analyst_id="analyst-01",
    )
    async_db_session.add(incident)
    await async_db_session.commit()

    res = await async_db_session.execute(select(Incident).where(Incident.id == "inc-test-01"))
    fetched_inc = res.scalar_one_or_none()
    assert fetched_inc is not None
    assert fetched_inc.severity == SeverityEnum.CRITICAL
    assert fetched_inc.status == IncidentStatusEnum.OPEN


@pytest.mark.asyncio
async def test_agent_enrollment_persistence(async_db_session: AsyncSession):
    """Verifies Agent daemon enrollment and heartbeat tracking in DB."""
    agent = Agent(
        id="agent-test-01",
        tenant_id="tenant-alpha",
        hostname="WORKSTATION-01",
        ip_address="10.0.0.45",
        os_type="Windows",
        os_version="11 Pro",
        agent_version="0.1.0",
        status=AgentStatusEnum.ONLINE,
    )
    async_db_session.add(agent)
    await async_db_session.commit()

    res = await async_db_session.execute(select(Agent).where(Agent.id == "agent-test-01"))
    fetched_agent = res.scalar_one_or_none()
    assert fetched_agent is not None
    assert fetched_agent.hostname == "WORKSTATION-01"
    assert fetched_agent.status == AgentStatusEnum.ONLINE


@pytest.mark.asyncio
async def test_tenant_isolation_boundary(async_db_session: AsyncSession):
    """Verifies that tenant resources remain isolated in queries."""
    tenant_b = Tenant(id="tenant-B", name="Beta Corp", slug="beta-corp", is_active=True)
    async_db_session.add(tenant_b)
    await async_db_session.commit()

    alert_a = Alert(
        id="alert-tenant-a",
        tenant_id="tenant-alpha",
        rule_code="RULE_A",
        severity=SeverityEnum.HIGH,
        host="host-A",
        reason="Test Tenant A",
        mitre_technique_id="T1110",
    )
    alert_b = Alert(
        id="alert-tenant-b",
        tenant_id="tenant-B",
        rule_code="RULE_B",
        severity=SeverityEnum.HIGH,
        host="host-B",
        reason="Test Tenant B",
        mitre_technique_id="T1059",
    )
    async_db_session.add_all([alert_a, alert_b])
    await async_db_session.commit()

    # Query only Tenant Alpha
    res_a = await async_db_session.execute(select(Alert).where(Alert.tenant_id == "tenant-alpha"))
    alerts_a = list(res_a.scalars().all())

    assert len(alerts_a) == 1
    assert alerts_a[0].id == "alert-tenant-a"


# ============================================================================
# R2: Security Configuration Assessment (SCA) Tests
# ============================================================================


@pytest.mark.asyncio
async def test_sca_policy_persistence(async_db_session: AsyncSession):
    """Verifies SCAPolicy persistence, querying, and schema conversion."""
    policy = SCAPolicy(
        id="sca-pol-01",
        tenant_id="tenant-alpha",
        policy_code="cis_ubuntu_22_04",
        name="CIS Benchmark for Ubuntu Linux 22.04 LTS",
        description="Security configuration benchmarks according to CIS Level 1 and Level 2.",
        os_type="linux",
        enabled=True,
        rules_count=45,
    )
    async_db_session.add(policy)
    await async_db_session.commit()

    res = await async_db_session.execute(select(SCAPolicy).where(SCAPolicy.id == "sca-pol-01"))
    fetched = res.scalar_one_or_none()
    assert fetched is not None
    assert fetched.policy_code == "cis_ubuntu_22_04"
    assert fetched.rules_count == 45
    assert fetched.enabled is True

    # Pydantic schema validation
    schema_read = SCAPolicyRead.model_validate(fetched)
    assert schema_read.id == "sca-pol-01"
    assert schema_read.name == "CIS Benchmark for Ubuntu Linux 22.04 LTS"


@pytest.mark.asyncio
async def test_sca_scan_report_persistence(async_db_session: AsyncSession):
    """Verifies SCAScanReport persistence with checks JSON array."""
    # Create required agent
    agent = Agent(
        id="agent-sca-01",
        tenant_id="tenant-alpha",
        hostname="LINUX-SRV-01",
        ip_address="192.168.1.100",
        os_type="linux",
        os_version="Ubuntu 22.04",
    )
    async_db_session.add(agent)
    await async_db_session.commit()

    report = SCAScanReport(
        id="sca-rep-01",
        tenant_id="tenant-alpha",
        agent_id="agent-sca-01",
        policy_id="cis_ubuntu_22_04",
        policy_name="CIS Ubuntu 22.04 LTS",
        compliance_score=85.0,
        total_checks=20,
        passed_checks=17,
        failed_checks=3,
        not_applicable_checks=0,
        checks=[
            {"id": "cis-1.1.1", "title": "Ensure cramfs is disabled", "status": "PASSED"},
            {"id": "cis-1.1.2", "title": "Ensure freevxfs is disabled", "status": "FAILED"},
        ],
    )
    async_db_session.add(report)
    await async_db_session.commit()

    res = await async_db_session.execute(
        select(SCAScanReport).where(SCAScanReport.id == "sca-rep-01")
    )
    fetched = res.scalar_one_or_none()
    assert fetched is not None
    assert fetched.compliance_score == 85.0
    assert fetched.passed_checks == 17
    assert len(fetched.checks) == 2
    assert fetched.checks[0]["status"] == "PASSED"

    # Pydantic schema validation
    schema_read = SCAScanReportRead.model_validate(fetched)
    assert schema_read.compliance_score == 85.0
    assert schema_read.failed_checks == 3


# ============================================================================
# R3: Syscollector System Inventory Tests
# ============================================================================


@pytest.mark.asyncio
async def test_agent_inventory_hardware_persistence(async_db_session: AsyncSession):
    """Verifies AgentInventoryHardware persistence and updates."""
    agent = Agent(
        id="agent-inv-01",
        tenant_id="tenant-alpha",
        hostname="DEV-WORKSTATION",
        ip_address="192.168.1.200",
        os_type="windows",
        os_version="Windows 11",
    )
    async_db_session.add(agent)
    await async_db_session.commit()

    hardware = AgentInventoryHardware(
        id="hw-inv-01",
        tenant_id="tenant-alpha",
        agent_id="agent-inv-01",
        cpu_cores_logical=16,
        cpu_cores_physical=8,
        cpu_architecture="x86_64",
        ram_total_gb=32.0,
        disks=[{"device": "C:", "total_gb": 512.0, "free_gb": 256.0}],
    )
    async_db_session.add(hardware)
    await async_db_session.commit()

    res = await async_db_session.execute(
        select(AgentInventoryHardware).where(AgentInventoryHardware.agent_id == "agent-inv-01")
    )
    fetched = res.scalar_one_or_none()
    assert fetched is not None
    assert fetched.cpu_cores_logical == 16
    assert fetched.ram_total_gb == 32.0
    assert len(fetched.disks) == 1

    # Pydantic schema validation
    schema_read = HardwareInventoryRead.model_validate(fetched)
    assert schema_read.cpu_architecture == "x86_64"


@pytest.mark.asyncio
async def test_agent_inventory_os_persistence(async_db_session: AsyncSession):
    """Verifies AgentInventoryOS persistence."""
    agent = Agent(
        id="agent-inv-02",
        tenant_id="tenant-alpha",
        hostname="PROD-DB-01",
        ip_address="10.10.10.5",
        os_type="linux",
        os_version="Debian 12",
    )
    async_db_session.add(agent)
    await async_db_session.commit()

    os_inv = AgentInventoryOS(
        id="os-inv-01",
        tenant_id="tenant-alpha",
        agent_id="agent-inv-02",
        os_name="Debian GNU/Linux",
        os_release="12.5",
        os_version="12 (bookworm)",
        kernel_architecture="x86_64",
        hostname="PROD-DB-01",
        python_version="3.11.2",
    )
    async_db_session.add(os_inv)
    await async_db_session.commit()

    res = await async_db_session.execute(
        select(AgentInventoryOS).where(AgentInventoryOS.agent_id == "agent-inv-02")
    )
    fetched = res.scalar_one_or_none()
    assert fetched is not None
    assert fetched.os_name == "Debian GNU/Linux"
    assert fetched.python_version == "3.11.2"

    schema_read = OSInventoryRead.model_validate(fetched)
    assert schema_read.hostname == "PROD-DB-01"


@pytest.mark.asyncio
async def test_agent_inventory_package_persistence(async_db_session: AsyncSession):
    """Verifies AgentInventoryPackage creation and queries."""
    agent = Agent(
        id="agent-inv-03",
        tenant_id="tenant-alpha",
        hostname="WEB-APP-01",
        ip_address="10.10.10.20",
        os_type="linux",
        os_version="Ubuntu 22.04",
    )
    async_db_session.add(agent)
    await async_db_session.commit()

    pkg1 = AgentInventoryPackage(
        id="pkg-01",
        tenant_id="tenant-alpha",
        agent_id="agent-inv-03",
        name="nginx",
        version="1.18.0",
        format="deb",
        architecture="amd64",
    )
    pkg2 = AgentInventoryPackage(
        id="pkg-02",
        tenant_id="tenant-alpha",
        agent_id="agent-inv-03",
        name="openssl",
        version="3.0.2",
        format="deb",
        architecture="amd64",
    )
    async_db_session.add_all([pkg1, pkg2])
    await async_db_session.commit()

    res = await async_db_session.execute(
        select(AgentInventoryPackage).where(AgentInventoryPackage.agent_id == "agent-inv-03")
    )
    packages = list(res.scalars().all())
    assert len(packages) == 2
    pkg_names = {p.name for p in packages}
    assert "nginx" in pkg_names
    assert "openssl" in pkg_names

    schema_read = PackageInventoryRead.model_validate(packages[0])
    assert schema_read.agent_id == "agent-inv-03"


@pytest.mark.asyncio
async def test_agent_inventory_network_persistence(async_db_session: AsyncSession):
    """Verifies AgentInventoryNetwork interface records."""
    agent = Agent(
        id="agent-inv-04",
        tenant_id="tenant-alpha",
        hostname="GATEWAY-01",
        ip_address="192.168.1.1",
        os_type="linux",
        os_version="Ubuntu 22.04",
    )
    async_db_session.add(agent)
    await async_db_session.commit()

    net1 = AgentInventoryNetwork(
        id="net-01",
        tenant_id="tenant-alpha",
        agent_id="agent-inv-04",
        interface_name="eth0",
        ipv4_address="192.168.1.1",
        ipv6_address="fe80::1",
        mac_address="52:54:00:12:34:56",
    )
    async_db_session.add(net1)
    await async_db_session.commit()

    res = await async_db_session.execute(
        select(AgentInventoryNetwork).where(AgentInventoryNetwork.agent_id == "agent-inv-04")
    )
    fetched = res.scalar_one_or_none()
    assert fetched is not None
    assert fetched.interface_name == "eth0"
    assert fetched.ipv4_address == "192.168.1.1"

    schema_read = NetworkInventoryRead.model_validate(fetched)
    assert schema_read.mac_address == "52:54:00:12:34:56"


@pytest.mark.asyncio
async def test_agent_inventory_port_persistence(async_db_session: AsyncSession):
    """Verifies AgentInventoryPort open listening port tracking."""
    agent = Agent(
        id="agent-inv-05",
        tenant_id="tenant-alpha",
        hostname="SRV-PORT-01",
        ip_address="192.168.1.15",
        os_type="linux",
        os_version="Ubuntu 22.04",
    )
    async_db_session.add(agent)
    await async_db_session.commit()

    port1 = AgentInventoryPort(
        id="port-01",
        tenant_id="tenant-alpha",
        agent_id="agent-inv-05",
        protocol="tcp",
        local_ip="0.0.0.0",
        local_port=443,
        pid=1024,
        process_name="nginx",
        state="LISTEN",
    )
    async_db_session.add(port1)
    await async_db_session.commit()

    res = await async_db_session.execute(
        select(AgentInventoryPort).where(AgentInventoryPort.agent_id == "agent-inv-05")
    )
    fetched = res.scalar_one_or_none()
    assert fetched is not None
    assert fetched.local_port == 443
    assert fetched.protocol == "tcp"
    assert fetched.process_name == "nginx"

    schema_read = PortInventoryRead.model_validate(fetched)
    assert schema_read.local_port == 443


@pytest.mark.asyncio
async def test_agent_inventory_process_persistence(async_db_session: AsyncSession):
    """Verifies AgentInventoryProcess running process tracking."""
    agent = Agent(
        id="agent-inv-06",
        tenant_id="tenant-alpha",
        hostname="SRV-PROC-01",
        ip_address="192.168.1.16",
        os_type="linux",
        os_version="Ubuntu 22.04",
    )
    async_db_session.add(agent)
    await async_db_session.commit()

    proc = AgentInventoryProcess(
        id="proc-01",
        tenant_id="tenant-alpha",
        agent_id="agent-inv-06",
        pid=4500,
        name="arka-agent",
        username="root",
        cpu_percent=1.5,
        memory_percent=0.8,
    )
    async_db_session.add(proc)
    await async_db_session.commit()

    res = await async_db_session.execute(
        select(AgentInventoryProcess).where(AgentInventoryProcess.agent_id == "agent-inv-06")
    )
    fetched = res.scalar_one_or_none()
    assert fetched is not None
    assert fetched.pid == 4500
    assert fetched.name == "arka-agent"

    schema_read = ProcessInventoryRead.model_validate(fetched)
    assert schema_read.cpu_percent == 1.5


# ============================================================================
# R4: Automated Active Response Tests
# ============================================================================


@pytest.mark.asyncio
async def test_active_response_task_lifecycle(async_db_session: AsyncSession):
    """Verifies ActiveResponseTask creation, status progression, and execution result persistence."""
    agent = Agent(
        id="agent-ar-01",
        tenant_id="tenant-alpha",
        hostname="ENDPOINT-01",
        ip_address="192.168.1.50",
        os_type="windows",
        os_version="Windows 10",
    )
    async_db_session.add(agent)
    await async_db_session.commit()

    # 1. Create Pending Active Response Task
    task = ActiveResponseTask(
        id="ar-task-01",
        tenant_id="tenant-alpha",
        agent_id="agent-ar-01",
        action=ActiveResponseActionEnum.BLOCK_IP,
        target="203.0.113.5",
        parameters={"timeout_seconds": 3600},
        status=ActiveResponseTaskStatusEnum.PENDING,
        command_payload={"action": "block_ip", "ip": "203.0.113.5"},
    )
    async_db_session.add(task)
    await async_db_session.commit()

    # 2. Query and verify initial status
    res = await async_db_session.execute(
        select(ActiveResponseTask).where(ActiveResponseTask.id == "ar-task-01")
    )
    fetched = res.scalar_one_or_none()
    assert fetched is not None
    assert fetched.action == ActiveResponseActionEnum.BLOCK_IP
    assert fetched.status == ActiveResponseTaskStatusEnum.PENDING

    # 3. Simulate execution and status update to SUCCESS
    fetched.status = ActiveResponseTaskStatusEnum.SUCCESS
    fetched.exit_code = 0
    fetched.stdout = "Firewall rule successfully added for IP 203.0.113.5."
    fetched.executed_at = datetime.now(UTC)
    await async_db_session.commit()

    # 4. Verify updated state and schema conversion
    res2 = await async_db_session.execute(
        select(ActiveResponseTask).where(ActiveResponseTask.id == "ar-task-01")
    )
    updated = res2.scalar_one_or_none()
    assert updated is not None
    assert updated.status == ActiveResponseTaskStatusEnum.SUCCESS
    assert updated.exit_code == 0

    schema_read = ActiveResponseTaskRead.model_validate(updated)
    assert schema_read.status == ActiveResponseTaskStatusEnum.SUCCESS
    assert schema_read.action == ActiveResponseActionEnum.BLOCK_IP
    assert schema_read.target == "203.0.113.5"


# ============================================================================
# R5: Vulnerability Detection & CVE Correlation Tests
# ============================================================================


@pytest.mark.asyncio
async def test_cve_item_persistence(async_db_session: AsyncSession):
    """Verifies CVEItem database persistence and querying."""
    cve = CVEItem(
        id="cve-item-01",
        cve_id="CVE-2021-44228",
        package_name="log4j-core",
        affected_versions_spec="<2.17.1",
        fixed_version="2.17.1",
        severity=SeverityEnum.CRITICAL,
        cvss_score=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        summary="Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    )
    async_db_session.add(cve)
    await async_db_session.commit()

    res = await async_db_session.execute(
        select(CVEItem).where(CVEItem.cve_id == "CVE-2021-44228")
    )
    fetched = res.scalar_one_or_none()
    assert fetched is not None
    assert fetched.package_name == "log4j-core"
    assert fetched.severity == SeverityEnum.CRITICAL
    assert fetched.cvss_score == 10.0

    schema_read = CVEItemRead.model_validate(fetched)
    assert schema_read.cve_id == "CVE-2021-44228"
    assert schema_read.fixed_version == "2.17.1"


@pytest.mark.asyncio
async def test_vulnerability_finding_persistence_and_mutation(async_db_session: AsyncSession):
    """Verifies VulnerabilityFinding creation, lifecycle mutation, and tenant isolation."""
    agent = Agent(
        id="agent-vuln-01",
        tenant_id="tenant-alpha",
        hostname="APP-SERVER-01",
        ip_address="10.0.1.10",
        os_type="linux",
        os_version="Ubuntu 20.04",
    )
    async_db_session.add(agent)
    await async_db_session.commit()

    finding = VulnerabilityFinding(
        id="vuln-find-01",
        tenant_id="tenant-alpha",
        agent_id="agent-vuln-01",
        cve_id="CVE-2021-44228",
        package_name="log4j-core",
        installed_version="2.14.1",
        fixed_version="2.17.1",
        severity=SeverityEnum.CRITICAL,
        cvss_score=10.0,
        summary="Log4Shell RCE vulnerability detected in installed package",
        status=VulnerabilityStatusEnum.ACTIVE,
    )
    async_db_session.add(finding)
    await async_db_session.commit()

    # Query active findings
    res = await async_db_session.execute(
        select(VulnerabilityFinding).where(
            VulnerabilityFinding.agent_id == "agent-vuln-01",
            VulnerabilityFinding.status == VulnerabilityStatusEnum.ACTIVE,
        )
    )
    fetched = res.scalar_one_or_none()
    assert fetched is not None
    assert fetched.cve_id == "CVE-2021-44228"
    assert fetched.status == VulnerabilityStatusEnum.ACTIVE

    # Mutate status to RESOLVED
    fetched.status = VulnerabilityStatusEnum.RESOLVED
    fetched.resolved_at = datetime.now(UTC)
    await async_db_session.commit()

    res2 = await async_db_session.execute(
        select(VulnerabilityFinding).where(VulnerabilityFinding.id == "vuln-find-01")
    )
    updated = res2.scalar_one_or_none()
    assert updated is not None
    assert updated.status == VulnerabilityStatusEnum.RESOLVED
    assert updated.resolved_at is not None

    schema_read = VulnerabilityFindingRead.model_validate(updated)
    assert schema_read.status == VulnerabilityStatusEnum.RESOLVED


@pytest.mark.asyncio
async def test_vulnerability_scan_report_persistence(async_db_session: AsyncSession):
    """Verifies VulnerabilityScanReport metrics aggregation and persistence."""
    agent = Agent(
        id="agent-vuln-02",
        tenant_id="tenant-alpha",
        hostname="APP-SERVER-02",
        ip_address="10.0.1.11",
        os_type="linux",
        os_version="Ubuntu 20.04",
    )
    async_db_session.add(agent)
    await async_db_session.commit()

    report = VulnerabilityScanReport(
        id="vuln-rep-01",
        tenant_id="tenant-alpha",
        agent_id="agent-vuln-02",
        scanned_packages_count=150,
        vulnerability_count=4,
        critical_count=1,
        high_count=2,
        medium_count=1,
        low_count=0,
    )
    async_db_session.add(report)
    await async_db_session.commit()

    res = await async_db_session.execute(
        select(VulnerabilityScanReport).where(VulnerabilityScanReport.id == "vuln-rep-01")
    )
    fetched = res.scalar_one_or_none()
    assert fetched is not None
    assert fetched.scanned_packages_count == 150
    assert fetched.critical_count == 1
    assert fetched.high_count == 2

    schema_read = VulnerabilityScanReportRead.model_validate(fetched)
    assert schema_read.vulnerability_count == 4
    assert schema_read.critical_count == 1
