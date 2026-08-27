# ruff: noqa: B008
"""
Vulnerability Detection & NVD CVE Correlation REST API Endpoints.
Provides software vulnerability scanning, tenant finding lifecycle queries,
historical scan report retrieval, and CVE knowledge catalog management.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.models import SeverityEnum, User, VulnerabilityStatusEnum
from app.schemas.schemas import (
    CVEItemRead,
    VulnerabilityFindingRead,
    VulnerabilityScanPayload,
    VulnerabilityScanReportRead,
    VulnerabilityStatusUpdate,
)
from app.services.vulnerability_engine import VulnerabilityEngine

router = APIRouter()


@router.post("/scan", status_code=status.HTTP_200_OK)
async def post_vulnerability_scan(
    payload: VulnerabilityScanPayload,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """
    Ingests software package inventory, performs semantic version correlation against CVE database,
    persists findings & scan report, and generates automated alerts for High/Critical vulnerabilities.
    """
    tenant_id = payload.tenant_id or current_user.tenant_id
    if not tenant_id or tenant_id == "default-tenant":
        tenant_id = current_user.tenant_id

    report, findings, alerts = await VulnerabilityEngine.correlate_and_persist(
        db=db,
        agent_id=payload.agent_id,
        tenant_id=tenant_id,
        packages=payload.packages,
    )

    return {
        "status": "success",
        "agent_id": payload.agent_id,
        "tenant_id": tenant_id,
        "report_id": report.id,
        "scanned_packages": report.scanned_packages_count,
        "vulnerability_count": report.vulnerability_count,
        "critical_count": report.critical_count,
        "high_count": report.high_count,
        "medium_count": report.medium_count,
        "low_count": report.low_count,
        "alerts_generated": len(alerts),
        "vulnerabilities": [
            {
                "id": f.id,
                "cve_id": f.cve_id,
                "package_name": f.package_name,
                "installed_version": f.installed_version,
                "fixed_version": f.fixed_version,
                "severity": f.severity.value,
                "cvss_score": f.cvss_score,
                "summary": f.summary,
                "status": f.status.value,
            }
            for f in findings
        ],
    }


@router.get("", response_model=list[VulnerabilityFindingRead])
async def list_vulnerabilities(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    agent_id: str | None = Query(None, description="Filter findings by agent ID"),
    status_filter: VulnerabilityStatusEnum | None = Query(
        None, alias="status", description="Filter by finding status"
    ),
    severity: SeverityEnum | None = Query(None, description="Filter by severity"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[VulnerabilityFindingRead]:
    """
    Retrieves all vulnerability findings for the analyst's tenant with zero fake data fallback.
    """
    findings = await VulnerabilityEngine.get_tenant_findings(
        db=db,
        tenant_id=current_user.tenant_id,
        agent_id=agent_id,
        status=status_filter,
        severity=severity,
        limit=limit,
        offset=offset,
    )
    return [VulnerabilityFindingRead.model_validate(f) for f in findings]


@router.get("/reports/{agent_id}", response_model=list[VulnerabilityScanReportRead])
async def get_agent_vulnerability_reports(
    agent_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    limit: int = Query(50, ge=1, le=200),
) -> list[VulnerabilityScanReportRead]:
    """
    Retrieves historical vulnerability scan reports for a specific endpoint agent.
    """
    reports = await VulnerabilityEngine.get_agent_reports(
        db=db,
        tenant_id=current_user.tenant_id,
        agent_id=agent_id,
        limit=limit,
    )
    return [VulnerabilityScanReportRead.model_validate(r) for r in reports]


@router.get("/cves", response_model=list[CVEItemRead])
async def list_cves(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],  # noqa: ARG001
    package_name: str | None = Query(None, description="Filter CVEs by package name"),
    severity: SeverityEnum | None = Query(None, description="Filter CVEs by severity"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[CVEItemRead]:
    """
    Retrieves registered CVE items from the knowledge database.
    """
    cve_items = await VulnerabilityEngine.get_all_cves(
        db=db,
        package_name=package_name,
        severity=severity,
        limit=limit,
        offset=offset,
    )
    return [CVEItemRead.model_validate(c) for c in cve_items]


@router.patch("/findings/{finding_id}/status", response_model=VulnerabilityFindingRead)
async def update_vulnerability_status(
    finding_id: str,
    payload: VulnerabilityStatusUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> VulnerabilityFindingRead:
    """
    Updates the status lifecycle of a vulnerability finding
    (ACTIVE -> MITIGATED -> RESOLVED -> FALSE_POSITIVE -> SUPPRESSED).
    """
    updated_finding = await VulnerabilityEngine.update_finding_status(
        db=db,
        finding_id=finding_id,
        tenant_id=current_user.tenant_id,
        status=payload.status,
        note=payload.note,
    )
    if not updated_finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability finding '{finding_id}' not found.",
        )
    return VulnerabilityFindingRead.model_validate(updated_finding)
