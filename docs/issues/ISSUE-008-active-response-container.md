# Issue #8: Implement Automated Active Response & Automated Containment Engine

- **Status**: `[IN_PROGRESS]`
- **Severity**: `HIGH`
- **Component**: `agent/arka_agent/active_response.py`, `backend/app/services/active_response_service.py`, `backend/app/api/v1/endpoints/active_response.py`
- **Reporter**: Lead Cybersecurity Architect
- **Target Branch**: `feature/8-active-response-container`

---

## Objective

Implement automated Active Response containment engine in ARKA:
1. **Active Response Executor**: Receives containment commands from backend and executes IP blocking (host firewall rule addition), process termination (`kill_process`), and user account lockout upon High/Critical alert detection.
2. **Active Response Service**: Dispatches automated containment actions upon rule triggering and logs response audit trails.
3. **Active Response REST API**: Exposes `/api/v1/active_response` REST API endpoint to view response history and trigger manual response actions.

---

## Acceptance Criteria

- [ ] `agent/arka_agent/active_response.py` executes IP blocking, process kill, and file quarantine commands safely.
- [ ] `backend/app/services/active_response_service.py` dispatches response triggers on High/Critical alerts.
- [ ] `backend/app/api/v1/endpoints/active_response.py` exposes REST API for active response logs and trigger triggers.
- [ ] `agent/tests/test_active_response.py` test suite passes 100%.
- [ ] Full `pytest` test suite passes 100%.
- [ ] `ruff`, `mypy`, `bandit` static checks pass with 0 errors.
