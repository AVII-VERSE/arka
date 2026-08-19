import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient

from app.models.models import Tenant


@pytest.mark.asyncio
async def test_event_ingestion_and_list(
    client: AsyncClient, test_tenant: Tenant, auth_headers: dict
):
    event_id = str(uuid.uuid4())
    payload = {
        "events": [
            {
                "event_id": event_id,
                "tenant_id": test_tenant.id,
                "agent_id": "agent-win-01",
                "timestamp": datetime.now(UTC).isoformat(),
                "source_type": "windows_event_log",
                "host": "DC01.corp.internal",
                "source_ip": "192.168.1.100",
                "user": "Administrator",
                "event_type": "authentication",
                "action": "logon_failed",
                "severity": "HIGH",
                "message": "Failed authentication attempt",
                "metadata": {"event_code": 4625},
            }
        ]
    }

    ingest_resp = await client.post("/api/v1/events/ingest", json=payload)
    assert ingest_resp.status_code == 202
    assert ingest_resp.json()["accepted"] == 1

    list_resp = await client.get("/api/v1/events", headers=auth_headers)
    assert list_resp.status_code == 200
    events = list_resp.json()
    assert len(events) >= 1
    matching = [e for e in events if e["event_id"] == event_id]
    assert len(matching) == 1
    assert matching[0]["host"] == "DC01.corp.internal"
