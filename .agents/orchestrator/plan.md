# Project Orchestration Plan: ARKA Enterprise SIEM & XDR

## 1. Survey Phase
- Dispatch 3 parallel Explorers:
  1. `teamwork_preview_explorer` 1 (Agent Architecture & Collectors): Inspect `agent/`, existing collectors, background tasks, data serialization, and test suite.
  2. `teamwork_preview_explorer` 2 (Backend Architecture & Services): Inspect `backend/app/`, DB models, FastAPI routers, services (`sca_engine`, `vulnerability_engine`, `active_response_service`, inventory APIs), Kafka/OpenSearch/PostgreSQL integration.
  3. `teamwork_preview_explorer` 3 (Test Suite, Static Analysis & CI/CD tooling): Inspect `pytest` configuration, test fixtures, `ruff`, `mypy`, `bandit` configurations, existing coverage and test layout.

## 2. Global Architecture & Decomposition (PROJECT.md & TEST_INFRA.md)
- Synthesize findings from the 3 explorers.
- Define feature inventory and interface contracts.
- Setup test runner, opaque-box E2E test plan across 4 tiers.

## 3. Implementation Track (Milestones R1 - R5)
- Milestone R1: Rootcheck & System Anomaly Harvester (`agent/arka_agent/collectors/rootcheck.py`)
- Milestone R2: Security Configuration Assessment (SCA) & CIS Benchmarks Engine (`agent/arka_agent/collectors/sca.py` and `backend/app/services/sca_engine.py`)
- Milestone R3: Syscollector System Inventory Harvester & REST APIs (`agent/arka_agent/collectors/syscollector.py`, `backend/app/api/v1/endpoints/inventory.py`)
- Milestone R4: Automated Active Response Container (`agent/arka_agent/active_response.py`, `backend/app/services/active_response_service.py`)
- Milestone R5: Vulnerability Detection & CVE Correlation Engine (`backend/app/services/vulnerability_engine.py`)

## 4. Rigorous Gating per Milestone
- Explorer -> Worker -> Reviewer -> Challenger -> Forensic Auditor -> Gate.
- Criteria: 100% tests pass, 0 ruff errors, 0 mypy errors, 0 bandit medium/high issues, clean forensic audit.

## 5. Acceptance & Delivery
- Run full test suite, linting, type checks, security scans.
- Provide final completion report to parent Sentinel.
