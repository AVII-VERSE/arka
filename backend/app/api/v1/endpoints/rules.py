"""
Detection Rule Engine Configuration Endpoints.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.models import DetectionRule, User
from app.schemas.schemas import DetectionRuleCreate, DetectionRuleRead

router = APIRouter()


@router.get("", response_model=list[DetectionRuleRead])
async def list_rules(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession | None, Depends(get_db)],
) -> list[DetectionRule]:
    """Lists security detection rules for tenant."""
    if db is None:
        return []
    try:
        result = await db.execute(
            select(DetectionRule).where(DetectionRule.tenant_id == current_user.tenant_id)
        )
        return list(result.scalars().all())
    except Exception:
        return []


@router.post("", response_model=DetectionRuleRead, status_code=status.HTTP_201_CREATED)
async def create_rule(
    payload: DetectionRuleCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> DetectionRule:
    """Creates a new deterministic detection rule."""
    rule = DetectionRule(
        tenant_id=current_user.tenant_id,
        rule_code=payload.rule_code,
        name=payload.name,
        description=payload.description,
        severity=payload.severity,
        enabled=payload.enabled,
        mitre_tactic=payload.mitre_tactic,
        mitre_technique_id=payload.mitre_technique_id,
        mitre_technique_name=payload.mitre_technique_name,
        conditions=payload.conditions,
        threshold=payload.threshold,
    )
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    return rule
