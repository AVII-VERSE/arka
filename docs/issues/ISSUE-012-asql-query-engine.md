# Issue #12: Implement ARKA Security Query Language (ASQL) Engine

- **Status**: `[RESOLVED]`
- **Severity**: `HIGH`
- **Component**: `backend/app/services/asql_engine.py`, `backend/app/api/v1/endpoints/query.py`
- **Reporter**: Lead Cybersecurity Architect
- **Target Branch**: `feature/12-asql-query-engine`

---

## Objective

Implement ARKA Security Query Language (ASQL) Engine:
1. **ASQL Parser & Executor**: Query engine (`backend/app/services/asql_engine.py`) parsing structured threat hunting queries (e.g. `severity = 'CRITICAL' AND rule_id = 'R1001' GROUP BY agent_id ORDER BY timestamp DESC LIMIT 50`) and translating them to OpenSearch / PostgreSQL queries.
2. **ASQL REST API Endpoint**: Endpoint `/api/v1/query` allowing SOC analysts to execute interactive hunt queries and receive aggregations.

---

## Acceptance Criteria

- [ ] `backend/app/services/asql_engine.py` parses and executes ASQL queries.
- [ ] `backend/app/api/v1/endpoints/query.py` provides REST API `/api/v1/query` endpoint.
- [ ] `backend/tests/test_asql_engine.py` test suite passes 100%.
- [ ] Full `pytest` test suite passes 100%.
- [ ] `ruff`, `mypy`, `bandit` static checks pass with 0 errors/issues.
