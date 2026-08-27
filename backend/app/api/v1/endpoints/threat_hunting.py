# ruff: noqa: B008
"""
Threat Hunting Playbooks REST API Endpoints.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.models import User
from app.services.threat_hunting_service import ThreatHuntingService

router = APIRouter()


class CreatePlaybookRequest(BaseModel):
    name: str
    description: str
    mitre_tactic: str
    mitre_technique_ids: list[str] = []
    hypothesis: str
    steps: list[dict[str, Any]] = []
    severity: str = "MEDIUM"
    tags: list[str] = []


class ExecutePlaybookRequest(BaseModel):
    analyst: str = "SOC Analyst"


@router.get("", response_model=list[dict[str, Any]])
async def list_playbooks(
    current_user: Annotated[User, Depends(get_current_user)],
) -> list[dict[str, Any]]:
    """Lists all threat hunting playbooks (built-in + custom) for the tenant."""
    return ThreatHuntingService.list_playbooks(current_user.tenant_id)


@router.get("/{playbook_id}")
async def get_playbook(
    playbook_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Retrieves a specific threat hunting playbook."""
    result = ThreatHuntingService.get_playbook(current_user.tenant_id, playbook_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' not found.")
    return result


@router.post("", status_code=201)
async def create_playbook(
    payload: CreatePlaybookRequest,
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Creates a new custom threat hunting playbook."""
    return ThreatHuntingService.create_playbook(
        current_user.tenant_id,
        payload.model_dump(),
    )


@router.post("/{playbook_id}/execute", status_code=201)
async def execute_playbook(
    playbook_id: str,
    payload: ExecutePlaybookRequest,
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Executes a threat hunting playbook against tenant telemetry."""
    result = ThreatHuntingService.execute_playbook(
        current_user.tenant_id,
        playbook_id,
        analyst=payload.analyst,
    )
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/executions/list", response_model=list[dict[str, Any]])
async def list_executions(
    current_user: Annotated[User, Depends(get_current_user)],
) -> list[dict[str, Any]]:
    """Lists all playbook execution records for the tenant."""
    return ThreatHuntingService.list_executions(current_user.tenant_id)


@router.get("/executions/{execution_id}")
async def get_execution(
    execution_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Retrieves a specific playbook execution record."""
    result = ThreatHuntingService.get_execution(current_user.tenant_id, execution_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Execution '{execution_id}' not found.")
    return result
