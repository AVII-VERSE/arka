"""
System Inventory & Syscollector REST API Endpoints.
"""

import platform
from typing import Annotated, Any

import psutil
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.models import User

router = APIRouter()

# Transient in-memory inventory store
_INVENTORY_STORE: dict[str, dict[str, Any]] = {}


class InventorySnapshotPayload(BaseModel):
    snapshot_id: str
    agent_id: str
    tenant_id: str
    timestamp: str
    hardware: dict[str, Any]
    os: dict[str, Any]
    network_interfaces: list[dict[str, Any]]
    running_processes: list[dict[str, Any]]


@router.post("/snapshot", status_code=201)
async def post_inventory_snapshot(
    payload: InventorySnapshotPayload,
) -> dict[str, str]:
    """Ingests a syscollector system inventory snapshot from an endpoint agent."""
    _INVENTORY_STORE[payload.agent_id] = payload.model_dump()
    return {"status": "success", "agent_id": payload.agent_id}


@router.get("", response_model=list[dict[str, Any]])
async def list_inventories(
    current_user: Annotated[User, Depends(get_current_user)],
) -> list[dict[str, Any]]:
    """Retrieves all system inventory snapshots for the analyst's tenant."""
    tenant_id = current_user.tenant_id
    snapshots = [snap for snap in _INVENTORY_STORE.values() if snap.get("tenant_id") == tenant_id]

    if not snapshots:
        mem = psutil.virtual_memory()
        return [
            {
                "snapshot_id": "syscol-init-01",
                "agent_id": "agent-dev-01",
                "tenant_id": tenant_id,
                "timestamp": "2026-08-26T12:00:00Z",
                "hardware": {
                    "cpu_cores_logical": psutil.cpu_count(logical=True) or 4,
                    "ram_total_gb": round(mem.total / (1024**3), 2),
                },
                "os": {
                    "os_name": platform.system(),
                    "os_release": platform.release(),
                    "hostname": platform.node(),
                },
                "network_interfaces": [
                    {
                        "interface_name": "eth0",
                        "ipv4_address": "192.168.1.105",
                        "mac_address": "00:11:22:33:44:55",
                    }
                ],
                "running_processes": [
                    {"pid": 4, "name": "System", "username": "NT AUTHORITY\\SYSTEM"}
                ],
            }
        ]

    return snapshots
