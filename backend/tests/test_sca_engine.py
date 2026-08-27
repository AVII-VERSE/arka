"""
Unit & Integration Tests for Backend SCA Engine and REST APIs.
Tests report persistence, query endpoints, tenant isolation, zero fake fallback, and summary aggregations.
"""

from datetime import UTC, datetime
from typing import Any

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, get_password_hash
from app.models.models import RoleEnum, Tenant, User
from app.schemas.schemas import SCAPolicyCreate
from app.services.sca_engine import SCAEngine


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


class TestSCAEngineService:
    """Service-level unit tests for SCAEngine."""

    @pytest.mark.asyncio
    async def test_persist_report_database(self, db_session: AsyncSession, test_tenant: Tenant):
        """Verifies SCAEngine persists scan reports to PostgreSQL/SQLite correctly."""
        report_data: dict[str, Any] = {
            "tenant_id": test_tenant.id,
            "agent_id": "agent-linux-01",
            "policy_id": "cis_linux_v2.0",
            "policy_name": "CIS Linux Server Benchmark",
            "compliance_score": 80.0,
            "total_checks": 10,
            "passed_checks": 8,
            "failed_checks": 2,
            "not_applicable_checks": 0,
            "checks": [
                {
                    "id": "CIS-LNX-1.1.1",
                    "title": "Verify /etc/passwd permissions",
                    "status": "PASSED",
                    "result": "PASS",
                },
                {
                    "id": "CIS-LNX-2.1.1",
                    "title": "Disable SSH Root Login",
                    "status": "FAILED",
                    "result": "FAIL",
                },
            ],
            "scanned_at": datetime.now(UTC).isoformat(),
        }

        report = await SCAEngine.persist_report(db_session, report_data)

        assert report.id is not None
        assert report.tenant_id == test_tenant.id
        assert report.agent_id == "agent-linux-01"
        assert report.compliance_score == 80.0
        assert report.total_checks == 10
        assert report.passed_checks == 8
        assert report.failed_checks == 2
        assert len(report.checks) == 2

    @pytest.mark.asyncio
    async def test_empty_database_returns_zero_fake_data(
        self, db_session: AsyncSession, test_tenant: Tenant
    ):
        """CRITICAL: Verifies empty database returns empty list, never mock/fake fallback dictionaries."""
        reports = await SCAEngine.get_tenant_reports(db_session, tenant_id=test_tenant.id)
        assert reports == []

        summary = await SCAEngine.get_tenant_summary(db_session, tenant_id=test_tenant.id)
        assert summary["total_scans"] == 0
        assert summary["average_compliance_score"] == 0.0
        assert summary["passed_checks_total"] == 0
        assert summary["failed_checks_total"] == 0
        assert summary["latest_reports"] == []

    @pytest.mark.asyncio
    async def test_tenant_summary_aggregation(
        self, db_session: AsyncSession, test_tenant: Tenant
    ):
        """Verifies average compliance score and check totals across multiple reports."""
        # Report 1: 100% (2 passed, 0 failed)
        r1 = {
            "tenant_id": test_tenant.id,
            "agent_id": "agent-01",
            "policy_id": "cis_v2",
            "policy_name": "CIS Policy",
            "passed_checks": 2,
            "failed_checks": 0,
            "not_applicable_checks": 1,
            "checks": [
                {"id": "c1", "status": "PASSED"},
                {"id": "c2", "status": "PASSED"},
                {"id": "c3", "status": "NOT_APPLICABLE"},
            ],
        }
        # Report 2: 50% (1 passed, 1 failed)
        r2 = {
            "tenant_id": test_tenant.id,
            "agent_id": "agent-02",
            "policy_id": "cis_v2",
            "policy_name": "CIS Policy",
            "passed_checks": 1,
            "failed_checks": 1,
            "not_applicable_checks": 0,
            "checks": [
                {"id": "c1", "status": "PASSED"},
                {"id": "c2", "status": "FAILED"},
            ],
        }

        await SCAEngine.persist_report(db_session, r1)
        await SCAEngine.persist_report(db_session, r2)

        summary = await SCAEngine.get_tenant_summary(db_session, tenant_id=test_tenant.id)
        assert summary["total_scans"] == 2
        # Average of 100.0 and 50.0 is 75.0
        assert summary["average_compliance_score"] == 75.0
        assert summary["passed_checks_total"] == 3
        assert summary["failed_checks_total"] == 1
        assert summary["not_applicable_checks_total"] == 1
        assert len(summary["latest_reports"]) == 2

    @pytest.mark.asyncio
    async def test_policy_management(self, db_session: AsyncSession, test_tenant: Tenant):
        """Verifies policy creation and retrieval."""
        policy_in = SCAPolicyCreate(
            policy_code="cis_ubuntu_2204",
            name="CIS Ubuntu Linux 22.04 LTS Benchmark",
            description="CIS OS benchmark profile for Ubuntu 22.04 LTS servers",
            os_type="linux",
            enabled=True,
            rules_count=15,
        )

        policy = await SCAEngine.create_policy(db_session, test_tenant.id, policy_in)
        assert policy.id is not None
        assert policy.policy_code == "cis_ubuntu_2204"

        policies = await SCAEngine.get_policies(db_session, test_tenant.id)
        assert len(policies) == 1
        assert policies[0].policy_code == "cis_ubuntu_2204"

        pol_by_code = await SCAEngine.get_policy_by_code(
            db_session, test_tenant.id, "cis_ubuntu_2204"
        )
        assert pol_by_code is not None
        assert pol_by_code.id == policy.id


class TestSCAEndpoints:
    """API router integration tests for /api/v1/sca."""

    @pytest.mark.asyncio
    async def test_post_sca_report_and_get_reports(
        self, client: AsyncClient, auth_headers: dict[str, str], test_tenant: Tenant
    ):
        """Verifies POST /api/v1/sca/report ingests report and GET /api/v1/sca retrieves it."""
        payload = {
            "policy_id": "cis_linux_v2.0",
            "policy_name": "CIS Linux Server Benchmark",
            "agent_id": "agent-alpha-01",
            "tenant_id": test_tenant.id,
            "compliance_score": 100.0,
            "total_checks": 2,
            "passed_checks": 2,
            "failed_checks": 0,
            "not_applicable_checks": 0,
            "checks": [
                {
                    "id": "CIS-LNX-1.1.1",
                    "title": "Verify /etc/passwd permissions",
                    "status": "PASSED",
                    "result": "PASS",
                },
                {
                    "id": "CIS-LNX-2.1.1",
                    "title": "Disable SSH Root Login",
                    "status": "PASSED",
                    "result": "PASS",
                },
            ],
        }

        # 1. Ingest report
        post_resp = await client.post(
            "/api/v1/sca/report",
            json=payload,
            headers=auth_headers,
        )
        assert post_resp.status_code == 201
        data = post_resp.json()
        assert data["status"] == "success"
        assert data["agent_id"] == "agent-alpha-01"
        assert "report_id" in data

        # 2. Query tenant reports
        get_resp = await client.get("/api/v1/sca", headers=auth_headers)
        assert get_resp.status_code == 200
        reports = get_resp.json()
        assert len(reports) == 1
        assert reports[0]["agent_id"] == "agent-alpha-01"
        assert reports[0]["compliance_score"] == 100.0
        assert len(reports[0]["checks"]) == 2

    @pytest.mark.asyncio
    async def test_empty_sca_endpoint_returns_empty_list(
        self, client: AsyncClient, auth_headers: dict[str, str]
    ):
        """Verifies GET /api/v1/sca on clean DB returns [] without mock fallback."""
        resp = await client.get("/api/v1/sca", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.asyncio
    async def test_empty_sca_summary_returns_zeroes(
        self, client: AsyncClient, auth_headers: dict[str, str]
    ):
        """Verifies GET /api/v1/sca/summary on clean DB returns 0 metrics without fake reports."""
        resp = await client.get("/api/v1/sca/summary", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_scans"] == 0
        assert data["average_compliance_score"] == 0.0
        assert data["passed_checks_total"] == 0
        assert data["failed_checks_total"] == 0
        assert data["latest_reports"] == []

    @pytest.mark.asyncio
    async def test_tenant_isolation_enforcement(
        self,
        client: AsyncClient,
        auth_headers: dict[str, str],
        second_auth_headers: dict[str, str],
        test_tenant: Tenant,
        second_tenant: Tenant,
    ):
        """Verifies Tenant A cannot see Tenant B's SCA scan reports."""
        # Tenant A report
        payload_a = {
            "policy_id": "cis_linux_v2.0",
            "policy_name": "CIS Linux Server Benchmark",
            "agent_id": "tenant-a-agent",
            "tenant_id": test_tenant.id,
            "checks": [{"id": "c1", "status": "PASSED"}],
        }
        resp_a = await client.post("/api/v1/sca/report", json=payload_a, headers=auth_headers)
        assert resp_a.status_code == 201

        # Tenant B report
        payload_b = {
            "policy_id": "cis_windows_v2.0",
            "policy_name": "CIS Windows Server Benchmark",
            "agent_id": "tenant-b-agent",
            "tenant_id": second_tenant.id,
            "checks": [{"id": "c2", "status": "PASSED"}],
        }
        resp_b = await client.post(
            "/api/v1/sca/report", json=payload_b, headers=second_auth_headers
        )
        assert resp_b.status_code == 201

        # Tenant A queries reports
        resp_list_a = await client.get("/api/v1/sca", headers=auth_headers)
        reports_a = resp_list_a.json()
        assert len(reports_a) == 1
        assert reports_a[0]["agent_id"] == "tenant-a-agent"

        # Tenant B queries reports
        resp_list_b = await client.get("/api/v1/sca", headers=second_auth_headers)
        reports_b = resp_list_b.json()
        assert len(reports_b) == 1
        assert reports_b[0]["agent_id"] == "tenant-b-agent"

        # Cross-tenant query by agent_id for Tenant B agent using Tenant A auth returns empty list
        resp_cross = await client.get(
            "/api/v1/sca/reports/tenant-b-agent", headers=auth_headers
        )
        assert resp_cross.status_code == 200
        assert resp_cross.json() == []

    @pytest.mark.asyncio
    async def test_get_agent_sca_reports(
        self, client: AsyncClient, auth_headers: dict[str, str], test_tenant: Tenant
    ):
        """Verifies GET /api/v1/sca/reports/{agent_id} returns reports filtered by agent."""
        payload1 = {
            "agent_id": "target-agent",
            "tenant_id": test_tenant.id,
            "checks": [{"id": "c1", "status": "PASSED"}],
        }
        payload2 = {
            "agent_id": "other-agent",
            "tenant_id": test_tenant.id,
            "checks": [{"id": "c2", "status": "PASSED"}],
        }
        await client.post("/api/v1/sca/report", json=payload1, headers=auth_headers)
        await client.post("/api/v1/sca/report", json=payload2, headers=auth_headers)

        resp = await client.get("/api/v1/sca/reports/target-agent", headers=auth_headers)
        assert resp.status_code == 200
        reports = resp.json()
        assert len(reports) == 1
        assert reports[0]["agent_id"] == "target-agent"

    @pytest.mark.asyncio
    async def test_sca_policies_endpoints(
        self, client: AsyncClient, auth_headers: dict[str, str]
    ):
        """Verifies POST /api/v1/sca/policies and GET /api/v1/sca/policies."""
        policy_payload = {
            "policy_code": "cis_rhel_9",
            "name": "CIS Red Hat Enterprise Linux 9 Benchmark",
            "description": "Hardening standard for RHEL 9 production hosts",
            "os_type": "linux",
            "enabled": True,
            "rules_count": 20,
        }

        post_resp = await client.post(
            "/api/v1/sca/policies", json=policy_payload, headers=auth_headers
        )
        assert post_resp.status_code == 201
        pol_data = post_resp.json()
        assert pol_data["policy_code"] == "cis_rhel_9"
        assert "id" in pol_data

        get_resp = await client.get("/api/v1/sca/policies", headers=auth_headers)
        assert get_resp.status_code == 200
        policies = get_resp.json()
        assert len(policies) == 1
        assert policies[0]["policy_code"] == "cis_rhel_9"
