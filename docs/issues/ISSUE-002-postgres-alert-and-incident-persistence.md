# Issue #2: Implement PostgreSQL Alert, Incident, Agent, and Audit Log Persistence Engine

- **Status**: `[RESOLVED]`
- **Severity**: `HIGH`
- **Component**: `backend/app/models/`, `backend/app/api/v1/endpoints/`, `backend/app/services/`
- **Reporter**: Lead Cybersecurity Architect
- **Target Branch**: `feature/2-postgres-alert-and-incident-persistence`

---

## Objective

Make PostgreSQL the authoritative metadata database for all Alert, Incident, Agent, and Audit Log records in ARKA SIEM. Ensure that all detection alerts generated, alert status mutations (`NEW` -> `ACKNOWLEDGED` -> `INVESTIGATING` -> `RESOLVED` -> `FALSE_POSITIVE`), incident creations, analyst notes, and agent enrollments persist permanently in PostgreSQL and survive backend process restarts without data loss.

---

## Current Behavior

When PostgreSQL is offline or unauthenticated, backend endpoints fall back to `_TRANSIENT_EVENT_STORE` in RAM. In-memory alerts and incidents clear whenever the FastAPI backend process restarts.

---

## Expected Behavior

1. The deterministic Detection Engine persists generated `Alert` objects directly into PostgreSQL `alerts` table.
2. Alert status mutations (`PATCH /api/v1/alerts/{id}`) update PostgreSQL `alerts` table and generate an immutable `AuditLog` row in PostgreSQL `audit_logs` table.
3. Incidents and analyst notes persist in PostgreSQL `incidents` table.
4. Endpoint agent enrollments and heartbeat timestamps persist in PostgreSQL `agents` table.
5. All database operations strictly maintain tenant context isolation (`tenant_id`).
6. **Backend Restart Test**: Ingest attack events -> Generate Alert -> Update status -> Restart FastAPI Backend -> Verify Alert, Status, and AuditLog still exist in PostgreSQL.

---

## Acceptance Criteria

- [ ] PostgreSQL `Alert`, `Incident`, `Agent`, and `AuditLog` models are fully integrated into FastAPI endpoints.
- [ ] Detection Engine writes generated alerts to PostgreSQL with fallback to SQLite local DB (`arka_local.db`).
- [ ] Alert status changes produce immutable `AuditLog` records in PostgreSQL.
- [ ] Pytest suite `backend/tests/test_persistence.py` passes 100%.
- [ ] Backend restart verification test passes 100%.
- [ ] All existing 10 Pytest tests pass 100%.

---

## Testing Plan

1. **Unit Tests**: `backend/tests/test_persistence.py` testing database session commits, alert status mutations, and audit log generation.
2. **Integration Test**: Backend restart verification test script checking database state retention.
