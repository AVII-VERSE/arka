"""
Incident Management Endpoints.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, verify_tenant_access
from app.models.models import AuditLog, Incident, User
from app.schemas.schemas import IncidentCreate, IncidentRead, IncidentUpdateStatus

router = APIRouter()


@router.get("", response_model=list[IncidentRead])
async def list_incidents(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession | None, Depends(get_db)],
    status_filter: str | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=200),
) -> list[Incident]:
    """Lists incidents for current tenant."""
    if db is None:
        return []
    try:
        query = select(Incident).where(Incident.tenant_id == current_user.tenant_id)
        if status_filter:
            query = query.where(Incident.status == status_filter.upper())

        query = query.order_by(Incident.created_at.desc()).limit(limit)
        result = await db.execute(query)
        return list(result.scalars().all())
    except Exception:
        return []


@router.post("", response_model=IncidentRead, status_code=status.HTTP_201_CREATED)
async def create_incident(
    payload: IncidentCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Incident:
    """Manually creates a new incident for investigation."""
    incident = Incident(
        tenant_id=current_user.tenant_id,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        assigned_analyst_id=payload.assigned_analyst_id or current_user.id,
        notes=[],
    )
    db.add(incident)
    await db.flush()

    audit = AuditLog(
        tenant_id=current_user.tenant_id,
        user_id=current_user.id,
        action="CREATE_INCIDENT",
        resource_type="Incident",
        resource_id=incident.id,
        details={"title": incident.title, "severity": incident.severity.value},
    )
    db.add(audit)
    await db.flush()
    await db.refresh(incident)
    return incident


@router.get("/{incident_id}", response_model=IncidentRead)
async def get_incident(
    incident_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Incident:
    """Retrieves incident details by ID."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    verify_tenant_access(current_user, incident.tenant_id)
    return incident


@router.patch("/{incident_id}", response_model=IncidentRead)
async def update_incident_status(
    incident_id: str,
    payload: IncidentUpdateStatus,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Incident:
    """Updates incident status and appends analyst notes."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    verify_tenant_access(current_user, incident.tenant_id)

    old_status = incident.status.value
    incident.status = payload.status

    notes = list(incident.notes or [])
    if payload.note:
        notes.append(
            {
                "user_id": current_user.id,
                "author": current_user.full_name,
                "text": payload.note,
            }
        )
    incident.notes = notes

    audit = AuditLog(
        tenant_id=incident.tenant_id,
        user_id=current_user.id,
        action="UPDATE_INCIDENT_STATUS",
        resource_type="Incident",
        resource_id=incident.id,
        details={"old_status": old_status, "new_status": payload.status.value},
    )
    db.add(audit)
    await db.flush()
    await db.refresh(incident)
    return incident
