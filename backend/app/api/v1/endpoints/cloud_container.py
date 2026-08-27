"""
Container & Cloud Security Harvester REST API Endpoints.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.models import User
from app.services.cloud_container_service import CloudContainerService

router = APIRouter()


class CloudContainerAuditPayload(BaseModel):
    agent_id: str
    tenant_id: str
    containers: list[dict[str, Any]]
    cloud_events: list[dict[str, Any]]


@router.post("/analyze", status_code=200)
async def analyze_cloud_container_telemetry(
    payload: CloudContainerAuditPayload,
) -> dict[str, Any]:
    """Ingests container and cloud audit telemetry and returns security risk analysis."""
    report = CloudContainerService.analyze_container_telemetry(
        payload.agent_id, payload.tenant_id, payload.containers, payload.cloud_events
    )
    return report


@router.get("", response_model=list[dict[str, Any]])
async def list_cloud_container_audits(
    current_user: Annotated[User, Depends(get_current_user)],
) -> list[dict[str, Any]]:
    """Retrieves container & cloud security audit logs for the user's tenant."""
    return CloudContainerService.get_tenant_cloud_container_reports(current_user.tenant_id)
