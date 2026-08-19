"""
Alert Management Endpoints.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, verify_tenant_access
from app.models.models import Alert, AuditLog, User
from app.schemas.schemas import AlertRead, AlertUpdateStatus

router = APIRouter()


@router.get("", response_model=list[AlertRead])
async def list_alerts(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    severity: str | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=200),
) -> list[Alert]:
    """Lists alerts scoped to the current user's tenant."""
    query = select(Alert).where(Alert.tenant_id == current_user.tenant_id)

    if severity:
        query = query.where(Alert.severity == severity.upper())
    if status_filter:
        query = query.where(Alert.status == status_filter.upper())

    query = query.order_by(Alert.created_at.desc()).limit(limit)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.get("/{alert_id}", response_model=AlertRead)
async def get_alert(
    alert_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Alert:
    """Gets alert details by ID."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found.",
        )
    verify_tenant_access(current_user, alert.tenant_id)
    return alert


@router.patch("/{alert_id}", response_model=AlertRead)
async def update_alert_status(
    alert_id: str,
    payload: AlertUpdateStatus,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Alert:
    """Mutates alert status and records an audit log entry."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found.",
        )
    verify_tenant_access(current_user, alert.tenant_id)

    old_status = alert.status.value
    alert.status = payload.status

    # Record Audit Trail
    audit_entry = AuditLog(
        tenant_id=alert.tenant_id,
        user_id=current_user.id,
        action="UPDATE_ALERT_STATUS",
        resource_type="Alert",
        resource_id=alert.id,
        details={
            "old_status": old_status,
            "new_status": payload.status.value,
        },
    )
    db.add(audit_entry)
    await db.flush()
    await db.refresh(alert)
    return alert
