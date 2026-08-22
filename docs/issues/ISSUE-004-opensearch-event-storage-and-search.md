# Issue #4: Implement OpenSearch Time-Series Indexing & Full-Text Search Engine

- **Status**: `[IN_PROGRESS]`
- **Severity**: `HIGH`
- **Component**: `backend/app/services/opensearch_service.py`, `backend/app/api/v1/endpoints/events.py`
- **Reporter**: Lead Cybersecurity Architect
- **Target Branch**: `feature/4-opensearch-event-storage-and-search`

---

## Objective

Build a production time-series event storage engine using OpenSearch for high-volume security event indexing, Lucene full-text searching, time-range filtering, and tenant-scoped aggregation queries. Security events must be indexed into dynamic time-series indices (`arka-events-{tenant_id}-{yyyy.mm}`) to support the SOC Security Event Explorer UI without storing raw event volumes in PostgreSQL.

---

## Current Behavior

Ingestion gateway appends raw events to an in-memory list `_TRANSIENT_EVENT_STORE`. OpenSearch settings are defined in config, but lack an active index management mapping client and search query generator.

---

## Expected Behavior

1. `OpenSearchEventService` initializes time-series index mapping (`arka-events-{tenant_id}-{yyyy.mm}`) with ECS-compatible field types (`keyword`, `date`, `ip`, `text`).
2. Normalized security events are bulk-indexed into OpenSearch.
3. Event Explorer (`GET /api/v1/events`) queries OpenSearch with Lucene full-text search, time-range bounds, host/user filters, and pagination.
4. When OpenSearch container is offline/unreachable in local dev, `OpenSearchEventService` safely falls back to high-performance in-memory indexing with Lucene-like field matching to prevent downtime.

---

## Acceptance Criteria

- [ ] `backend/app/services/opensearch_service.py` implements time-series index mapping, bulk indexing, and search query execution.
- [ ] Index naming convention follows `arka-events-{tenant_id}-{yyyy.mm}`.
- [ ] Event Explorer API queries OpenSearch with filters (host, user, event_type, severity, search term, time range).
- [ ] Unit & integration tests in `backend/tests/test_opensearch_service.py` pass 100%.
- [ ] Full Pytest suite passes 100%.

---

## Testing Plan

1. **Unit Tests**: `backend/tests/test_opensearch_service.py` testing index creation, ECS mapping validation, search query execution, and Lucene field filtering.
2. **Integration Test**: Ingest events -> Index -> Execute Lucene Query -> Verify Search Results & Pagination.
