# Issue #7: Implement Security Configuration Assessment (SCA) & CIS Benchmarks Engine

- **Status**: `[IN_PROGRESS]`
- **Severity**: `HIGH`
- **Component**: `agent/arka_agent/collectors/sca.py`, `backend/app/services/sca_engine.py`, `backend/app/api/v1/endpoints/sca.py`
- **Reporter**: Lead Cybersecurity Architect
- **Target Branch**: `feature/7-sca-and-cis-benchmarks`

---

## Objective

Implement Security Configuration Assessment (SCA) scanner and CIS benchmark policy compliance engine into ARKA:
1. **SCA Scanner**: Audits OS security policy settings (e.g., SSH password authentication disabled, minimum password length >= 14, Firewall enabled, UAC enabled on Windows).
2. **Compliance Engine**: Computes overall endpoint compliance score (Pass percentage, Fail count, Not Applicable count) and provides remediation instructions.
3. **SCA REST API**: Exposes `/api/v1/sca` REST API endpoint to query compliance reports.

---

## Acceptance Criteria

- [ ] `agent/arka_agent/collectors/sca.py` evaluates system security configuration checks against CIS benchmarks.
- [ ] `backend/app/services/sca_engine.py` aggregates compliance scores (Pass/Fail/N-A).
- [ ] `backend/app/api/v1/endpoints/sca.py` exposes REST API for SCA policy compliance reports.
- [ ] `agent/tests/test_sca_benchmarks.py` test suite passes 100%.
- [ ] Full `pytest` test suite passes 100%.
- [ ] `ruff`, `mypy`, `bandit` static checks pass with 0 errors.
