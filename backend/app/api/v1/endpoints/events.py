"""
Security Event Ingestion & Explorer Endpoints.
"""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.models import Alert, User
from app.schemas.schemas import IngestEventsRequest, IngestEventsResponse, NormalizedEvent
from app.services.detection_engine import DetectionEngine
from app.services.kafka_pipeline import kafka_consumer, kafka_producer
from app.services.opensearch_service import opensearch_service

router = APIRouter()

# In-memory transient event storage for fallback / test mode
_TRANSIENT_EVENT_STORE: list[NormalizedEvent] = []
_TRANSIENT_ALERT_STORE: list[Alert] = []

detection_engine = DetectionEngine()


@router.post(
    "/ingest",
    response_model=IngestEventsResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_events(
    request: IngestEventsRequest,
    db: Annotated[AsyncSession | None, Depends(get_db)] = None,
) -> IngestEventsResponse:
    """High-throughput Ingestion Gateway Endpoint.
    Validates incoming batch security events, stamps ingestion time,
    publishes to Kafka event pipeline, indexes into OpenSearch,
    and evaluates detection engine rules to generate alerts.
    """
    accepted = 0
    failed = 0
    errors: list[str] = []

    now = datetime.now(UTC)
    for event in request.events:
        try:
            event.ingested_at = now
            _TRANSIENT_EVENT_STORE.append(event)

            # Publish to Kafka streaming pipeline & OpenSearch
            event_dict = event.model_dump()
            kafka_producer.publish_event("arka.events.raw", event_dict)
            kafka_consumer.process_raw_event(event_dict)
            opensearch_service.index_event(event)

            # Evaluate Detection Rules
            alert = detection_engine.evaluate_event(event_dict)
            if alert:
                _TRANSIENT_ALERT_STORE.append(alert)
                if db is not None:
                    try:
                        db.add(alert)
                        await db.commit()
                    except Exception:
                        pass

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

    # Query OpenSearch index / transient store
    results = opensearch_service.search_events(
        tenant_id=tenant_id,
        search_query=search,
        host=host,
        severity=severity,
        event_type=event_type,
        limit=limit,
    )

    if results:
        normalized_list = []
        for r in results:
            try:
                # Remove internal _index metadata key
                clean_r = {k: v for k, v in r.items() if k != "_index"}
                normalized_list.append(NormalizedEvent(**clean_r))
            except Exception:
                pass
        if normalized_list:
            return normalized_list

    # Fallback filter from transient event store
    filtered = [e for e in _TRANSIENT_EVENT_STORE if e.tenant_id == tenant_id]

    if severity:
        filtered = [e for e in filtered if e.severity == severity.upper()]
    if host:
        filtered = [e for e in filtered if e.host == host]
    if event_type:
        filtered = [e for e in filtered if e.event_type == event_type]
    if search:
        s_lower = search.lower()
        filtered = [
            e
            for e in filtered
            if s_lower in e.message.lower()
            or (e.process and s_lower in e.process.lower())
            or (e.source_ip and s_lower in e.source_ip.lower())
            or s_lower in e.host.lower()
        ]

    return sorted(filtered, key=lambda x: x.timestamp, reverse=True)[:limit]
