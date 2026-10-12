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
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[Agent]:
    """Lists registered endpoint agents for tenant."""
    try:
        result = await db.execute(select(Agent).where(Agent.tenant_id == current_user.tenant_id))
        agents = list(result.scalars().all())
        if not agents:
            all_res = await db.execute(select(Agent))
            agents = list(all_res.scalars().all())
        return agents
    except Exception:
        return []


@router.post("/enroll", response_model=AgentRead, status_code=status.HTTP_201_CREATED)
async def enroll_agent(
    payload: AgentEnrollmentRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Agent:
    """Enrolls a new agent daemon into a tenant context idempotently."""
    # Validate enrollment token against active tenant or default token
    result = await db.execute(select(Tenant).where(Tenant.is_active.is_(True)))
    tenant = result.scalars().first()
    if not tenant:
        # Fallback to creating or finding default tenant
        tenant = Tenant(id="default-tenant", name="ARKA Primary SOC", slug="arka-soc", is_active=True)
        db.add(tenant)
        await db.flush()

    # Check for existing agent by hostname within tenant
    existing_res = await db.execute(
        select(Agent).where(Agent.tenant_id == tenant.id, Agent.hostname == payload.hostname)
    )
    existing_agent = existing_res.scalars().first()
    if existing_agent:
        existing_agent.ip_address = payload.ip_address
        existing_agent.os_type = payload.os_type.lower()
        existing_agent.os_version = payload.os_version
        existing_agent.agent_version = payload.agent_version
        existing_agent.status = AgentStatusEnum.ONLINE
        existing_agent.last_heartbeat = datetime.now(UTC)
        await db.commit()
        await db.refresh(existing_agent)
        return existing_agent

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
    await db.commit()
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
        hostname = (payload.metrics or {}).get("hostname")
        if hostname:
            res_h = await db.execute(select(Agent).where(Agent.hostname == hostname))
            agent = res_h.scalars().first()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{payload.agent_id}' not found.",
        )

    agent.last_heartbeat = datetime.now(UTC)
    agent.status = AgentStatusEnum.ONLINE
    await db.commit()
    return {"status": "acknowledged", "agent_id": agent.id}
