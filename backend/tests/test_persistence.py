"""
Tests for PostgreSQL & Database Persistence of Alerts, Incidents, Agents, and Audit Logs.
"""

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.models.models import (
    Agent,
    AgentStatusEnum,
    Alert,
    AlertStatusEnum,
    AuditLog,
    Incident,
    IncidentStatusEnum,
    SeverityEnum,
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
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


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
    alert_a = Alert(
        id="alert-tenant-a",
        tenant_id="tenant-A",
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

    # Query only Tenant A
    res_a = await async_db_session.execute(select(Alert).where(Alert.tenant_id == "tenant-A"))
    alerts_a = list(res_a.scalars().all())

    assert len(alerts_a) == 1
    assert alerts_a[0].id == "alert-tenant-a"
