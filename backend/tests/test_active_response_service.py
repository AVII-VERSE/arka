"""
Unit & Integration Tests for Backend Active Response Service & REST Endpoints.
Tests task lifecycle state machines, automated alert containment triggers, manual dispatch,
strict IP/PID safety whitelist guards, agent polling & callbacks, audit log generation, and zero fake fallback data.
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, get_password_hash
from app.models.models import (
    ActiveResponseActionEnum,
    ActiveResponseTaskStatusEnum,
    Alert,
    AlertStatusEnum,
    AuditLog,
    RoleEnum,
    SeverityEnum,
    Tenant,
    User,
)
from app.schemas.schemas import (
    ActiveResponseStatusUpdate,
    ActiveResponseTriggerRequest,
)
from app.services.active_response_service import ActiveResponseService


@pytest_asyncio.fixture
async def second_tenant(db_session: AsyncSession) -> Tenant:
    """Creates an isolated second tenant for multi-tenancy verification."""
    tenant = Tenant(name="Beta Security Corp", slug="beta-security-corp")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)
    return tenant


@pytest_asyncio.fixture
async def second_user(db_session: AsyncSession, second_tenant: Tenant) -> User:
    """Creates a user belonging to second tenant."""
    user = User(
        email="analyst@betacorp.org",
        hashed_password=get_password_hash("BetaSecretPassword123!"),
        full_name="Beta Analyst",
        tenant_id=second_tenant.id,
        role=RoleEnum.SECURITY_ANALYST,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
def second_auth_headers(second_user: User) -> dict[str, str]:
    """JWT auth headers for second tenant."""
    token = create_access_token(
        subject=second_user.id,
        tenant_id=second_user.tenant_id,
        role=second_user.role.value,
    )
    return {"Authorization": f"Bearer {token}"}


class TestActiveResponseServiceUnit:
    """Service-level unit tests for ActiveResponseService logic and state machine."""

    @pytest.mark.asyncio
    async def test_task_full_lifecycle(self, db_session: AsyncSession, test_tenant: Tenant, test_user: User):
        """Verifies complete task lifecycle: PENDING -> DISPATCHED -> SUCCESS with audit logging."""
        # 1. Create task (PENDING)
        req = ActiveResponseTriggerRequest(
            agent_id="agent-prod-01",
            action=ActiveResponseActionEnum.BLOCK_IP,
            target="198.51.100.88",
            parameters={"duration_seconds": 300},
        )
        task = await ActiveResponseService.create_task(
            db=db_session,
            tenant_id=test_tenant.id,
            payload=req,
            user_id=test_user.id,
        )
        assert task.status == ActiveResponseTaskStatusEnum.PENDING
        assert task.target == "198.51.100.88"
        assert task.action == ActiveResponseActionEnum.BLOCK_IP

        # Verify audit log created
        audits = (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_id == task.id,
                    AuditLog.action == "CREATE_ACTIVE_RESPONSE_TASK",
                )
            )
        ).scalars().all()
        assert len(audits) == 1

        # 2. Agent polls pending task -> transitions to DISPATCHED
        polled = await ActiveResponseService.get_pending_tasks_for_agent(
            db=db_session,
            agent_id="agent-prod-01",
            tenant_id=test_tenant.id,
        )
        assert len(polled) == 1
        assert polled[0].id == task.id
        assert polled[0].status == ActiveResponseTaskStatusEnum.DISPATCHED
        assert polled[0].dispatched_at is not None

        # 3. Agent reports completion -> transitions to SUCCESS
        update_payload = ActiveResponseStatusUpdate(
            task_id=task.id,
            status=ActiveResponseTaskStatusEnum.SUCCESS,
            exit_code=0,
            stdout="Rule added successfully",
            message="Active Response: Block applied.",
        )
        updated_task = await ActiveResponseService.update_task_result(
            db=db_session,
            task_id=task.id,
            update_data=update_payload,
            tenant_id=test_tenant.id,
        )
        assert updated_task.status == ActiveResponseTaskStatusEnum.SUCCESS
        assert updated_task.exit_code == 0
        assert updated_task.executed_at is not None

        # Verify completion audit log
        res_audits = (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_id == task.id,
                    AuditLog.action == "ACTIVE_RESPONSE_TASK_RESULT_RECORDED",
                )
            )
        ).scalars().all()
        assert len(res_audits) == 1

    @pytest.mark.asyncio
    async def test_automated_alert_containment_dispatch(self, db_session: AsyncSession, test_tenant: Tenant):
        """Verifies CRITICAL and BRUTE_FORCE_LOGIN alerts automatically trigger active response tasks."""
        # 1. CRITICAL Alert
        crit_alert = Alert(
            tenant_id=test_tenant.id,
            rule_code="RANSOMWARE_BEHAVIOR_DETECTED",
            severity=SeverityEnum.CRITICAL,
            host="agent-prod-02",
            source_ip="203.0.113.77",
            reason="Mass file encryption activity detected",
            mitre_technique_id="T1486",
            status=AlertStatusEnum.NEW,
        )
        db_session.add(crit_alert)
        await db_session.commit()
        await db_session.refresh(crit_alert)

        task_crit = await ActiveResponseService.dispatch_alert_response(db_session, crit_alert)
        assert task_crit is not None
        assert task_crit.status == ActiveResponseTaskStatusEnum.PENDING
        assert task_crit.target == "203.0.113.77"
        assert task_crit.trigger_alert_id == crit_alert.id

        # 2. BRUTE_FORCE_LOGIN Alert (HIGH severity)
        brute_alert = Alert(
            tenant_id=test_tenant.id,
            rule_code="BRUTE_FORCE_LOGIN",
            severity=SeverityEnum.HIGH,
            host="agent-prod-02",
            source_ip="198.51.100.22",
            reason="10 failed SSH logins in 30 seconds",
            mitre_technique_id="T1110",
            status=AlertStatusEnum.NEW,
        )
        db_session.add(brute_alert)
        await db_session.commit()
        await db_session.refresh(brute_alert)

        task_brute = await ActiveResponseService.dispatch_alert_response(db_session, brute_alert)
        assert task_brute is not None
        assert task_brute.target == "198.51.100.22"

        # 3. LOW Severity Alert (Should NOT trigger response)
        low_alert = Alert(
            tenant_id=test_tenant.id,
            rule_code="UNUSUAL_LOGIN_TIME",
            severity=SeverityEnum.LOW,
            host="agent-prod-02",
            source_ip="198.51.100.99",
            reason="User logged in outside business hours",
            mitre_technique_id="T1078",
            status=AlertStatusEnum.NEW,
        )
        db_session.add(low_alert)
        await db_session.commit()
        await db_session.refresh(low_alert)

        task_low = await ActiveResponseService.dispatch_alert_response(db_session, low_alert)
        assert task_low is None

    @pytest.mark.asyncio
    async def test_ip_and_pid_safety_guards(self, db_session: AsyncSession, test_tenant: Tenant, test_user: User):
        """Verifies backend safety validator blocks attempts to target loopback IPs or system PIDs."""
        # Loopback IP safety check
        req_loopback = ActiveResponseTriggerRequest(
            agent_id="agent-01",
            action=ActiveResponseActionEnum.BLOCK_IP,
            target="127.0.0.1",
        )
        task_ip = await ActiveResponseService.create_task(db_session, test_tenant.id, req_loopback, test_user.id)
        assert task_ip.status == ActiveResponseTaskStatusEnum.FAILED
        assert "Safety Policy Violation" in task_ip.message

        # System PID safety check
        req_pid = ActiveResponseTriggerRequest(
            agent_id="agent-01",
            action=ActiveResponseActionEnum.KILL_PROCESS,
            target="4",
        )
        task_pid = await ActiveResponseService.create_task(db_session, test_tenant.id, req_pid, test_user.id)
        assert task_pid.status == ActiveResponseTaskStatusEnum.FAILED
        assert "Safety Policy Violation" in task_pid.message


class TestActiveResponseAPIs:
    """REST API integration tests for /api/v1/active_response endpoints."""

    @pytest.mark.asyncio
    async def test_zero_fake_data_empty_state(self, client: AsyncClient, auth_headers: dict[str, str]):
        """Verifies GET /api/v1/active_response/tasks returns empty list [] on empty DB."""
        resp = await client.get("/api/v1/active_response/tasks", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

        resp_logs = await client.get("/api/v1/active_response", headers=auth_headers)
        assert resp_logs.status_code == 200
        assert resp_logs.json() == []

    @pytest.mark.asyncio
    async def test_manual_trigger_api(self, client: AsyncClient, auth_headers: dict[str, str]):
        """Verifies POST /api/v1/active_response/trigger creates task and returns 201."""
        payload = {
            "agent_id": "agent-dmz-01",
            "action": "block_ip",
            "target": "203.0.113.100",
            "parameters": {"duration_seconds": 600},
        }
        resp = await client.post("/api/v1/active_response/trigger", json=payload, headers=auth_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert data["action"] == "block_ip"
        assert data["target"] == "203.0.113.100"
        assert data["status"] == "PENDING"
        assert "id" in data

    @pytest.mark.asyncio
    async def test_agent_poll_and_result_callback_apis(self, client: AsyncClient, auth_headers: dict[str, str]):
        """Verifies agent pending task poll and execution result submission."""
        # 1. Trigger containment task
        payload = {
            "agent_id": "agent-dmz-02",
            "action": "kill_process",
            "target": "8842",
        }
        resp_trigger = await client.post("/api/v1/active_response/trigger", json=payload, headers=auth_headers)
        task_id = resp_trigger.json()["id"]

        # 2. Agent poll endpoint
        resp_poll = await client.get("/api/v1/active_response/agents/agent-dmz-02/pending", headers=auth_headers)
        assert resp_poll.status_code == 200
        polled_tasks = resp_poll.json()
        assert len(polled_tasks) == 1
        assert polled_tasks[0]["id"] == task_id
        assert polled_tasks[0]["status"] == "DISPATCHED"

        # 3. Agent reports result
        result_payload = {
            "task_id": task_id,
            "status": "SUCCESS",
            "exit_code": 0,
            "stdout": "PID 8842 terminated",
            "message": "Process successfully terminated.",
        }
        resp_res = await client.post(
            f"/api/v1/active_response/tasks/{task_id}/result",
            json=result_payload,
            headers=auth_headers,
        )
        assert resp_res.status_code == 200
        res_data = resp_res.json()
        assert res_data["status"] == "SUCCESS"
        assert res_data["exit_code"] == 0

        # 4. Get task by ID
        resp_get = await client.get(f"/api/v1/active_response/tasks/{task_id}", headers=auth_headers)
        assert resp_get.status_code == 200
        assert resp_get.json()["id"] == task_id
        assert resp_get.json()["status"] == "SUCCESS"

    @pytest.mark.asyncio
    async def test_multi_tenant_isolation(
        self,
        client: AsyncClient,
        auth_headers: dict[str, str],
        second_auth_headers: dict[str, str],
    ):
        """Verifies strict tenant isolation: Tenant B cannot see or manipulate Tenant A's tasks."""
        # Tenant A creates task
        payload = {
            "agent_id": "agent-alpha-01",
            "action": "block_ip",
            "target": "198.51.100.5",
        }
        resp_a = await client.post("/api/v1/active_response/trigger", json=payload, headers=auth_headers)
        task_id = resp_a.json()["id"]

        # Tenant B lists tasks -> should be empty
        resp_b_list = await client.get("/api/v1/active_response/tasks", headers=second_auth_headers)
        assert resp_b_list.status_code == 200
        assert resp_b_list.json() == []

        # Tenant B attempts to fetch Tenant A's task -> 404
        resp_b_get = await client.get(f"/api/v1/active_response/tasks/{task_id}", headers=second_auth_headers)
        assert resp_b_get.status_code == 404
