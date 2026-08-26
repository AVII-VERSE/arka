# Pull Request #6: Implement Agent Rootcheck Security Scanner & Syscollector System Inventory Engine

- **Branch**: `feature/6-rootcheck-and-syscollector-inventory` -> `develop`
- **Fixes**: `Fixes #6`
- **Status**: `[MERGED]`
- **Author**: Lead Cybersecurity Architect & SIEM Engineer

---

## Summary

This Pull Request implements:
1. **Rootcheck Security Scanner**: Endpoint security collector scanning for suspicious rootkit file paths (`/dev/.static`, `/tmp/.hidden`), promiscuous network listening sockets on backdoor ports, and hidden process anomalies.
2. **Syscollector System Inventory Harvester**: System inventory collector gathering hardware (CPU, RAM, Disks), OS details, network interface addresses (IPv4, IPv6, MAC), and active running processes.
3. **Inventory REST API**: REST endpoint `GET /api/v1/inventory` and `POST /api/v1/inventory/snapshot` allowing analysts and agent daemons to store and inspect inventory snapshots.

---

## Technical Changes

1. **Rootcheck Scanner**: `agent/arka_agent/collectors/rootcheck.py`
2. **Syscollector Inventory**: `agent/arka_agent/collectors/syscollector.py`
3. **Inventory REST Endpoint**: `backend/app/api/v1/endpoints/inventory.py`
4. **Test Suite Addition**: `agent/tests/test_rootcheck_and_syscollector.py` covering rootcheck anomaly detection and system inventory snapshot collection.

---

## Verification & Testing

```bash
# Executed full test suite
pytest backend/tests agent/tests
# Result: 25 passed in 1.17s

ruff check backend agent
# Result: All checks passed!

bandit -r backend/app agent/arka_agent -ll
# Result: No security issues identified.
```

All acceptance criteria for Issue #6 have been satisfied and verified.
