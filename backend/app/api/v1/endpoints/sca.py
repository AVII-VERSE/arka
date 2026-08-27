"""
Security Configuration Assessment (SCA) REST API Endpoints.
Provides CIS benchmark report ingestion, report queries, compliance summary, and policy management.
"""

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.models import User
from app.schemas.schemas import SCAPolicyCreate, SCAPolicyRead, SCAScanReportRead, SCASummary
from app.services.sca_engine import SCAEngine

router = APIRouter()


class SCAPayload(BaseModel):
    policy_id: str = "cis_benchmark_v2.0"
    policy_name: str = "CIS Operating System Hardening Policy"
    agent_id: str
    tenant_id: str = "default-tenant"
    timestamp: str | None = None
    scanned_at: datetime | str | None = None
    compliance_score: float | None = None
    total_checks: int | None = None
    passed_checks: int | None = None
    failed_checks: int | None = None
    not_applicable_checks: int | None = None
    summary: dict[str, Any] = Field(default_factory=dict)
    checks: list[dict[str, Any]] = Field(default_factory=list)


@router.post("/report", status_code=201)
async def post_sca_report(
    payload: SCAPayload,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Ingests and persists an SCA CIS benchmark report from an endpoint agent."""
    report_dict = payload.model_dump()
    if not payload.tenant_id or payload.tenant_id == "default-tenant":
        report_dict["tenant_id"] = current_user.tenant_id

    report = await SCAEngine.persist_report(db, report_dict)
    return {
        "status": "success",
        "agent_id": payload.agent_id,
        "report_id": report.id,
        "compliance_score": report.compliance_score,
    }


@router.get("", response_model=list[SCAScanReportRead])
async def list_sca_reports(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    agent_id: str | None = Query(None, description="Filter reports by agent ID"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[SCAScanReportRead]:
    """Retrieves all SCA CIS benchmark reports for the analyst's tenant."""
    reports = await SCAEngine.get_tenant_reports(
        db=db,
        tenant_id=current_user.tenant_id,
        agent_id=agent_id,
        limit=limit,
        offset=offset,
    )
    return [SCAScanReportRead.model_validate(r) for r in reports]


@router.get("/summary", response_model=SCASummary)
async def get_sca_summary(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    agent_id: str | None = Query(None, description="Filter summary by agent ID"),
) -> SCASummary:
    """Retrieves aggregated tenant-wide compliance posture summary."""
    summary_data = await SCAEngine.get_tenant_summary(
        db=db,
        tenant_id=current_user.tenant_id,
        agent_id=agent_id,
    )
    return SCASummary(
        agent_id=summary_data.get("agent_id"),
        total_scans=summary_data["total_scans"],
        average_compliance_score=summary_data["average_compliance_score"],
        passed_checks_total=summary_data["passed_checks_total"],
        failed_checks_total=summary_data["failed_checks_total"],
        not_applicable_checks_total=summary_data["not_applicable_checks_total"],
        latest_reports=[SCAScanReportRead.model_validate(r) for r in summary_data.get("latest_reports", [])],
    )


@router.get("/reports/{agent_id}", response_model=list[SCAScanReportRead])
async def get_agent_sca_reports(
    agent_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    limit: int = Query(50, ge=1, le=200),
) -> list[SCAScanReportRead]:
    """Retrieves historical SCA reports for a specific endpoint agent."""
    reports = await SCAEngine.get_agent_reports(
        db=db,
        tenant_id=current_user.tenant_id,
        agent_id=agent_id,
        limit=limit,
    )
    return [SCAScanReportRead.model_validate(r) for r in reports]


@router.get("/policies", response_model=list[SCAPolicyRead])
async def list_sca_policies(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> list[SCAPolicyRead]:
    """Retrieves all active SCA compliance policies for the tenant."""
    policies = await SCAEngine.get_policies(db=db, tenant_id=current_user.tenant_id)
    return [SCAPolicyRead.model_validate(p) for p in policies]


@router.post("/policies", response_model=SCAPolicyRead, status_code=201)
async def create_sca_policy(
    policy_in: SCAPolicyCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> SCAPolicyRead:
    """Creates a new SCA compliance policy for the tenant."""
    policy = await SCAEngine.create_policy(
        db=db,
        tenant_id=current_user.tenant_id,
        policy_in=policy_in,
    )
    return SCAPolicyRead.model_validate(policy)

