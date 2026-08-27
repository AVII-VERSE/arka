# Pull Request #12: Implement ARKA Security Query Language (ASQL) Engine

- **Branch**: `feature/12-asql-query-engine` -> `develop`
- **Fixes**: `Fixes #12`
- **Status**: `[MERGED]`
- **Author**: Lead Cybersecurity Architect & SIEM Engineer

---

## Summary

This Pull Request implements:
1. **ASQL Query Parsing & Execution Engine**: `backend/app/services/asql_engine.py` parsing domain-specific SIEM threat hunting query expressions supporting `WHERE`, `GROUP BY`, `ORDER BY`, `LIMIT`, and boolean logic operators.
2. **ASQL REST API Endpoint**: `backend/app/api/v1/endpoints/query.py` exposing REST API `POST /api/v1/query` for interactive threat hunting.

---

## Technical Changes

1. **ASQL Engine**: `backend/app/services/asql_engine.py`
2. **ASQL REST API Endpoint**: `backend/app/api/v1/endpoints/query.py`
3. **Test Suite Addition**: `backend/tests/test_asql_engine.py` testing query AST parsing and dataset filtering.

---

## Verification & Testing

```bash
# Executed full test suite
pytest backend/tests agent/tests
# Result: 103 passed, 1 skipped in 15.42s

ruff check backend agent
# Result: All checks passed!

bandit -r backend/app agent/arka_agent -ll
# Result: No security issues identified.
```

All acceptance criteria for Issue #12 have been satisfied and verified.
