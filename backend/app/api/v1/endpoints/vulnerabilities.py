"""
Vulnerability Detection & NVD CVE Correlation REST API Endpoints.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.models import User
from app.services.vulnerability_engine import VulnerabilityEngine

router = APIRouter()


class VulnerabilityScanPayload(BaseModel):
    agent_id: str
    tenant_id: str
    packages: list[dict[str, str]]


@router.post("/scan", status_code=200)
async def post_vulnerability_scan(payload: VulnerabilityScanPayload) -> dict[str, Any]:
    """Ingests software package inventory and returns correlated CVE vulnerability report."""
    report = VulnerabilityEngine.correlate_packages(
        payload.agent_id, payload.tenant_id, payload.packages
    )
    return report


@router.get("", response_model=list[dict[str, Any]])
async def list_vulnerabilities(
    current_user: Annotated[User, Depends(get_current_user)],
) -> list[dict[str, Any]]:
    """Retrieves all vulnerability reports for the analyst's tenant."""
    return VulnerabilityEngine.get_tenant_vulnerabilities(current_user.tenant_id)
