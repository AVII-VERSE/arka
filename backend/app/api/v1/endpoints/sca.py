"""
Security Configuration Assessment (SCA) REST API Endpoints.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.models import User
from app.services.sca_engine import SCAEngine

router = APIRouter()


class SCAPayload(BaseModel):
    policy_id: str
    policy_name: str
    agent_id: str
    tenant_id: str
    timestamp: str
    compliance_score: float
    summary: dict[str, Any]
    checks: list[dict[str, Any]]


@router.post("/report", status_code=201)
async def post_sca_report(payload: SCAPayload) -> dict[str, str]:
    """Ingests an SCA CIS benchmark report from an endpoint agent."""
    SCAEngine.register_report(payload.agent_id, payload.model_dump())
    return {"status": "success", "agent_id": payload.agent_id}


@router.get("", response_model=list[dict[str, Any]])
async def list_sca_reports(
    current_user: Annotated[User, Depends(get_current_user)],
) -> list[dict[str, Any]]:
    """Retrieves all SCA CIS benchmark reports for the analyst's tenant."""
    return SCAEngine.get_tenant_reports(current_user.tenant_id)
