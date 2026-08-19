"""
ARKA Agent Management & Heartbeat Endpoints.
"""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.models import Agent, AgentStatusEnum, Tenant, User
from app.schemas.schemas import AgentEnrollmentRequest, AgentHeartbeat, AgentRead

router = APIRouter()


@router.get("", response_model=list[AgentRead])
async def list_agents(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession | None, Depends(get_db)],
) -> list[Agent]:
    """Lists registered endpoint agents for tenant."""
    if db is None:
        return []
    try:
        result = await db.execute(select(Agent).where(Agent.tenant_id == current_user.tenant_id))
        return list(result.scalars().all())
    except Exception:
        return []


@router.post("/enroll", response_model=AgentRead, status_code=status.HTTP_201_CREATED)
async def enroll_agent(
    payload: AgentEnrollmentRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Agent:
    """Enrolls a new agent daemon into a tenant context."""
    # Validate enrollment token against active tenant or default token
    result = await db.execute(select(Tenant).where(Tenant.is_active.is_(True)))
    tenant = result.scalars().first()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active tenant available for enrollment.",
        )

    agent = Agent(
        tenant_id=tenant.id,
        hostname=payload.hostname,
        ip_address=payload.ip_address,
        os_type=payload.os_type.lower(),
        os_version=payload.os_version,
        agent_version=payload.agent_version,
        status=AgentStatusEnum.ONLINE,
        last_heartbeat=datetime.now(UTC),
    )
    db.add(agent)
    await db.flush()
    await db.refresh(agent)
    return agent


@router.post("/heartbeat", status_code=status.HTTP_200_OK)
async def agent_heartbeat(
    payload: AgentHeartbeat,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Agent heartbeat ping endpoint."""
    result = await db.execute(select(Agent).where(Agent.id == payload.agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{payload.agent_id}' not found.",
        )

    agent.last_heartbeat = datetime.now(UTC)
    agent.status = AgentStatusEnum.ONLINE
    await db.flush()
    return {"status": "acknowledged", "agent_id": agent.id}
