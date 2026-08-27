"""
System Inventory & Syscollector REST API Endpoints.
Provides snapshot ingestion and sub-resource queries for hardware, OS metadata,
installed packages, network interfaces, open ports, and running processes.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.models import User
from app.schemas.schemas import (
    AgentInventorySummary,
    HardwareInventoryRead,
    InventorySnapshotPayload,
    NetworkInventoryRead,
    OSInventoryRead,
    PackageInventoryRead,
    PortInventoryRead,
    ProcessInventoryRead,
)
from app.services.inventory_service import InventoryService

router = APIRouter()


@router.post("/snapshot", status_code=status.HTTP_201_CREATED)
async def post_inventory_snapshot(
    payload: InventorySnapshotPayload,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Ingests a syscollector system inventory snapshot from an endpoint agent."""
    tenant_id = payload.tenant_id or current_user.tenant_id
    result = await InventoryService.ingest_snapshot(db, payload, tenant_id_override=tenant_id)
    return result


@router.get("", response_model=list[AgentInventorySummary])
async def list_inventories(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[AgentInventorySummary]:
    """Retrieves system inventory summaries for all agents in the tenant."""
    return await InventoryService.get_inventory_summary(db, current_user.tenant_id)


@router.get("/{agent_id}/hardware", response_model=HardwareInventoryRead)
async def get_agent_hardware(
    agent_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> HardwareInventoryRead:
    """Retrieves hardware inventory for a specific endpoint agent."""
    hw = await InventoryService.get_hardware(db, agent_id, current_user.tenant_id)
    if not hw:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Hardware inventory for agent '{agent_id}' not found.",
        )
    return HardwareInventoryRead.model_validate(hw)


@router.get("/{agent_id}/os", response_model=OSInventoryRead)
async def get_agent_os(
    agent_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> OSInventoryRead:
    """Retrieves operating system metadata inventory for a specific endpoint agent."""
    os_info = await InventoryService.get_os(db, agent_id, current_user.tenant_id)
    if not os_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OS inventory for agent '{agent_id}' not found.",
        )
    return OSInventoryRead.model_validate(os_info)


@router.get("/{agent_id}/packages", response_model=list[PackageInventoryRead])
async def get_agent_packages(
    agent_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[PackageInventoryRead]:
    """Retrieves all installed software packages for a specific endpoint agent."""
    packages = await InventoryService.get_packages(db, agent_id, current_user.tenant_id)
    return [PackageInventoryRead.model_validate(p) for p in packages]


@router.get("/{agent_id}/network", response_model=list[NetworkInventoryRead])
async def get_agent_network(
    agent_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[NetworkInventoryRead]:
    """Retrieves network interfaces inventory for a specific endpoint agent."""
    interfaces = await InventoryService.get_network(db, agent_id, current_user.tenant_id)
    return [NetworkInventoryRead.model_validate(i) for i in interfaces]


@router.get("/{agent_id}/ports", response_model=list[PortInventoryRead])
async def get_agent_ports(
    agent_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[PortInventoryRead]:
    """Retrieves open listening ports and active network sockets for a specific endpoint agent."""
    ports = await InventoryService.get_ports(db, agent_id, current_user.tenant_id)
    return [PortInventoryRead.model_validate(p) for p in ports]


@router.get("/{agent_id}/processes", response_model=list[ProcessInventoryRead])
async def get_agent_processes(
    agent_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[ProcessInventoryRead]:
    """Retrieves active running processes for a specific endpoint agent."""
    processes = await InventoryService.get_processes(db, agent_id, current_user.tenant_id)
    return [ProcessInventoryRead.model_validate(p) for p in processes]
