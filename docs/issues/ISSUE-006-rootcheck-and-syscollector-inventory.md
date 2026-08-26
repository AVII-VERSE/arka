# Issue #6: Implement Agent Rootcheck Security Scanner & Syscollector System Inventory Engine

- **Status**: `[IN_PROGRESS]`
- **Severity**: `HIGH`
- **Component**: `agent/arka_agent/collectors/rootcheck.py`, `agent/arka_agent/collectors/syscollector.py`, `backend/app/api/v1/endpoints/inventory.py`
- **Reporter**: Lead Cybersecurity Architect
- **Target Branch**: `feature/6-rootcheck-and-syscollector-inventory`

---

## Objective

Enhance the ARKA Endpoint Security Telemetry Agent with:
1. **Rootcheck Security Scanner**: Scans endpoints for hidden processes, promiscuous network sockets, suspicious file paths (`/tmp/.hidden`, `/var/tmp/.rootkit`), and system anomalies.
2. **Syscollector System Inventory Harvester**: Collects comprehensive hardware (CPU, RAM, Disks), OS details, installed software packages, open listening network ports, running process lists, and user accounts.
3. **Inventory REST API**: Exposes `/api/v1/inventory` endpoint in backend to store and query inventory snapshots.

---

## Acceptance Criteria

- [ ] `agent/arka_agent/collectors/rootcheck.py` detects system anomalies and rootkit indicators.
- [ ] `agent/arka_agent/collectors/syscollector.py` harvests complete system inventory.
- [ ] `backend/app/api/v1/endpoints/inventory.py` provides REST API endpoint for system inventory querying.
- [ ] `agent/tests/test_rootcheck_and_syscollector.py` test suite passes 100%.
- [ ] Full `pytest` test suite passes 100%.
- [ ] `ruff`, `mypy`, `bandit` checks pass with 0 errors/issues.
