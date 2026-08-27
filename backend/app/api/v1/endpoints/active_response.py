"""
Active Response & Automated Containment REST API Endpoints.
Provides task dispatch, agent polling, execution result callbacks, and audit trail inspection.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.core.exceptions import ARKAException
from app.models.models import ActiveResponseTaskStatusEnum, User
from app.schemas.schemas import (
    ActiveResponseStatusUpdate,
    ActiveResponseTaskRead,
    ActiveResponseTriggerRequest,
)
from app.services.active_response_service import ActiveResponseService

router = APIRouter()


@router.post(
    "/trigger",
    response_model=ActiveResponseTaskRead,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger active response action",
)
async def trigger_active_response(
    payload: ActiveResponseTriggerRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Any:
    """Manually triggers an active response containment action on a target host."""
    return await ActiveResponseService.create_task(
        db=db,
        tenant_id=current_user.tenant_id,
        payload=payload,
        user_id=current_user.id,
    )


@router.get(
    "/tasks",
    response_model=list[ActiveResponseTaskRead],
    summary="List active response containment tasks",
)
async def list_active_response_tasks(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    status: ActiveResponseTaskStatusEnum | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    """Lists active response tasks for the current tenant with optional status filtering."""
    return await ActiveResponseService.get_tasks(
        db=db,
        tenant_id=current_user.tenant_id,
        status=status,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/tasks/{task_id}",
    response_model=ActiveResponseTaskRead,
    summary="Get active response task details",
)
async def get_active_response_task(
    task_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Any:
    """Retrieves detailed status and execution metrics for a specific active response task."""
    task = await ActiveResponseService.get_task_by_id(
        db=db,
        task_id=task_id,
        tenant_id=current_user.tenant_id,
    )
    if not task:
        raise ARKAException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Active response task '{task_id}' not found.",
            error_code="TASK_NOT_FOUND",
        )
    return task


@router.get(
    "/agents/{agent_id}/pending",
    response_model=list[ActiveResponseTaskRead],
    summary="Agent pending tasks poll endpoint",
)
async def poll_pending_agent_tasks(
    agent_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Any:
    """Agent poll endpoint to retrieve pending containment tasks and transition them to DISPATCHED."""
    return await ActiveResponseService.get_pending_tasks_for_agent(
        db=db,
        agent_id=agent_id,
        tenant_id=current_user.tenant_id,
    )


@router.post(
    "/tasks/{task_id}/result",
    response_model=ActiveResponseTaskRead,
    summary="Agent task execution callback",
)
async def record_task_result(
    task_id: str,
    payload: ActiveResponseStatusUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Any:
    """Endpoint for agent daemon to submit active response containment execution results."""
    return await ActiveResponseService.update_task_result(
        db=db,
        task_id=task_id,
        update_data=payload,
        tenant_id=current_user.tenant_id,
    )


@router.get(
    "",
    response_model=list[ActiveResponseTaskRead],
    summary="List active response containment logs",
)
async def list_active_response_logs(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=1000)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    """Retrieves audit trail of active response actions for tenant with zero fake data."""
    return await ActiveResponseService.get_tasks(
        db=db,
        tenant_id=current_user.tenant_id,
        limit=limit,
        offset=offset,
    )
