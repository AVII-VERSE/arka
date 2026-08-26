"""
Active Response & Automated Containment REST API Endpoints.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.models import User
from app.services.active_response_service import ActiveResponseService

router = APIRouter()


class TriggerResponsePayload(BaseModel):
    agent_id: str
    action: str
    target: str


@router.post("/trigger", status_code=200)
async def trigger_active_response(
    payload: TriggerResponsePayload,
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Manually triggers an active response containment action on a target agent."""
    response_entry = ActiveResponseService.dispatch_alert_response(
        {
            "id": "manual-trigger",
            "tenant_id": current_user.tenant_id,
            "agent_id": payload.agent_id,
            "severity": "CRITICAL",
            "rule_code": "MANUAL_CONTAINMENT_DISPATCH",
            "source_ip": payload.target,
        }
    )
    return response_entry or {"status": "dispatched", "target": payload.target}


@router.get("", response_model=list[dict[str, Any]])
async def list_active_response_logs(
    current_user: Annotated[User, Depends(get_current_user)],
) -> list[dict[str, Any]]:
    """Retrieves audit trail of automated active response actions for tenant."""
    return ActiveResponseService.get_tenant_logs(current_user.tenant_id)
