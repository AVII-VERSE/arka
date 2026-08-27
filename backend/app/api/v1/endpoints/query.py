"""
ARKA Security Query Language (ASQL) Interactive Threat Hunting Endpoint.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.models import User
from app.services.asql_engine import ASQLEngine

router = APIRouter()


class ASQLQueryPayload(BaseModel):
    query: str
    target_dataset: str = "alerts"  # options: alerts, events, incidents, inventory


@router.post("", status_code=200)
async def execute_asql_query(
    payload: ASQLQueryPayload,
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Executes an interactive ASQL threat hunting query."""
    # Default sample dataset for query execution
    sample_dataset = [
        {
            "id": "alt-01",
            "rule_id": "R1001",
            "severity": "CRITICAL",
            "agent_id": "agent-01",
            "tenant_id": current_user.tenant_id,
            "timestamp": "2026-08-27T09:00:00Z",
        },
        {
            "id": "alt-02",
            "rule_id": "R1002",
            "severity": "HIGH",
            "agent_id": "agent-02",
            "tenant_id": current_user.tenant_id,
            "timestamp": "2026-08-27T09:05:00Z",
        },
        {
            "id": "alt-03",
            "rule_id": "R1001",
            "severity": "CRITICAL",
            "agent_id": "agent-01",
            "tenant_id": current_user.tenant_id,
            "timestamp": "2026-08-27T09:10:00Z",
        },
    ]

    return ASQLEngine.execute_query(payload.query, sample_dataset)
