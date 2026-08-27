# BRIEFING — 2026-08-27T04:10:45Z

## Mission
Implement Milestone M4 (R3: Syscollector System Inventory Harvester & REST APIs) including SyscollectorHarvester in agent, relational atomic inventory persistence service and REST endpoints in backend with zero fake data, and full test suite.

## 🔒 My Identity
- Archetype: implementer
- Roles: implementer, qa, specialist
- Working directory: d:/ARKA/.agents/worker_m4
- Original parent: 2bac8ff3-063e-412a-ae38-31580c635708
- Milestone: M4 (Syscollector System Inventory Harvester & REST APIs)

## 🔒 Key Constraints
- Subclasses BaseCollector(name="syscollector", enabled=enabled).
- Real software inventory parsing across Debian/Ubuntu, RedHat/CentOS, Alpine, Windows Registry, Python environment.
- Ports, interfaces, hardware, OS, running processes real harvesting.
- InventoryService with AsyncSession, atomic relational persistence (upsert/replace per agent) across canonical inventory models: AgentInventoryHardware, AgentInventoryOS, AgentInventoryPackage, AgentInventoryNetwork, AgentInventoryPort, AgentInventoryProcess.
- Eliminate all server psutil fallback mocks — return 404/empty lists when no data in DB.
- Full test suites for agent collector and backend service/API endpoints.
- Pass ruff, mypy, bandit, pytest.
- Zero fake data / dummy implementations.

## Current Parent
- Conversation ID: 2bac8ff3-063e-412a-ae38-31580c635708
- Updated: not yet

## Task Summary
- **What to build**: SyscollectorHarvester in `agent/arka_agent/collectors/syscollector.py`, `InventoryService` in `backend/app/services/inventory_service.py`, endpoints in `backend/app/api/v1/endpoints/inventory.py`, agent tests in `agent/tests/test_syscollector.py`, backend tests in `backend/tests/test_inventory_service.py`.
- **Success criteria**: All tests pass, linting/typing/security checks clean, zero mocks on server endpoints.
- **Interface contracts**: `PROJECT.md`, `ORIGINAL_REQUEST.md`, explorer handoffs.
- **Code layout**: Agent collectors in `agent/arka_agent/collectors/`, backend services in `backend/app/services/`, endpoints in `backend/app/api/v1/endpoints/`.

## Key Decisions Made
- [TBD]

## Artifact Index
- `d:/ARKA/.agents/worker_m4/DISPATCH.md` — Assignment dispatch
- `d:/ARKA/.agents/worker_m4/progress.md` — Liveness & step tracker
- `d:/ARKA/.agents/worker_m4/handoff.md` — Handoff report

## Change Tracker
- **Files modified**: None yet
- **Build status**: Pending
- **Pending issues**: None

## Quality Status
- **Build/test result**: Pending
- **Lint status**: Pending
- **Tests added/modified**: Pending

## Loaded Skills
- None
