"""
Command & Syscall Audit REST API Endpoints.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.models import User
from app.services.command_audit_service import CommandAuditService

router = APIRouter()


class CommandAuditPayload(BaseModel):
    agent_id: str
    tenant_id: str
    events: list[dict[str, Any]]


@router.post("/analyze", status_code=200)
async def analyze_command_telemetry(payload: CommandAuditPayload) -> dict[str, Any]:
    """Ingests process command executions and returns threat analysis."""
    report = CommandAuditService.analyze_command_events(
        payload.agent_id, payload.tenant_id, payload.events
    )
    return report


@router.get("", response_model=list[dict[str, Any]])
async def list_command_audits(
    current_user: Annotated[User, Depends(get_current_user)],
) -> list[dict[str, Any]]:
    """Retrieves command execution audit logs for the user's tenant."""
    return CommandAuditService.get_tenant_command_audits(current_user.tenant_id)
