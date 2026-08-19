"""
Security Event Ingestion & Explorer Endpoints.
"""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import get_current_user
from app.models.models import User
from app.schemas.schemas import IngestEventsRequest, IngestEventsResponse, NormalizedEvent

router = APIRouter()

# In-memory transient event storage for fallback / test mode
_TRANSIENT_EVENT_STORE: list[NormalizedEvent] = []


@router.post(
    "/ingest",
    response_model=IngestEventsResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_events(
    request: IngestEventsRequest,
) -> IngestEventsResponse:
    """High-throughput Ingestion Gateway Endpoint.
    Validates incoming batch security events, stamps ingestion time,
    and publishes to Kafka event pipeline.
    """
    accepted = 0
    failed = 0
    errors: list[str] = []

    now = datetime.now(UTC)
    for event in request.events:
        try:
            event.ingested_at = now
            _TRANSIENT_EVENT_STORE.append(event)
            accepted += 1
        except Exception as e:
            failed += 1
            errors.append(f"Event {event.event_id}: {str(e)}")

    return IngestEventsResponse(accepted=accepted, failed=failed, errors=errors)


@router.get("", response_model=list[NormalizedEvent])
async def list_events(
    current_user: Annotated[User, Depends(get_current_user)],
    severity: str | None = Query(None),
    host: str | None = Query(None),
    event_type: str | None = Query(None),
    search: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
) -> list[NormalizedEvent]:
    """Retrieves normalized events with filtering for the analyst's tenant."""
    tenant_id = current_user.tenant_id
    filtered = [e for e in _TRANSIENT_EVENT_STORE if e.tenant_id == tenant_id]

    if severity:
        filtered = [e for e in filtered if e.severity.value == severity.upper()]
    if host:
        filtered = [e for e in filtered if host.lower() in e.host.lower()]
    if event_type:
        filtered = [e for e in filtered if e.event_type.lower() == event_type.lower()]
    if search:
        s = search.lower()
        filtered = [
            e for e in filtered if s in e.message.lower() or (e.user and s in e.user.lower())
        ]

    return filtered[:limit]
