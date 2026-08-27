## 2026-08-26T09:19:53Z
You are teamwork_preview_worker #3 for Milestone M3 (R2: Security Configuration Assessment & CIS Benchmarks Engine).

Your Working Directory: d:/ARKA/.agents/worker_m3
Original Request Path: d:/ARKA/.agents/ORIGINAL_REQUEST.md
Project Scope Document: d:/ARKA/PROJECT.md
Survey Reference: d:/ARKA/.agents/explorer_survey_1/handoff.md § 4.3 and d:/ARKA/.agents/explorer_survey_2/handoff.md § 2.1

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Scope & Exclusively Owned Files:
- `agent/arka_agent/collectors/sca.py`
- `backend/app/services/sca_engine.py`
- `backend/app/api/v1/endpoints/sca.py`
- `agent/tests/test_sca_benchmarks.py`
- `backend/tests/test_sca_engine.py`

Tasks:
1. Initialize `progress.md` and `BRIEFING.md` in `d:/ARKA/.agents/worker_m3`.
2. Implement `SCAScanner` in `agent/arka_agent/collectors/sca.py`:
   - Subclasses `BaseCollector(name="sca", enabled=enabled)`.
   - Implement multi-platform CIS rule evaluators: file content regex matching, file permissions and ownership bits (`stat.S_ISUID`, mode `<= 0644`, etc.), Windows registry queries, safe subprocess command evaluation (`sysctl`, `netsh`, `ufw`).
   - Implement Linux CIS Benchmark profile (CIS Linux v2.0): SSH `PermitRootLogin no`, Protocol 2, password expiration & length in login.defs / pam, `/etc/passwd` permissions, `/etc/shadow` permissions, `/etc/sudoers` permissions, IP forwarding disabled, host firewall status.
   - Implement Windows CIS Benchmark profile: Windows Defender Firewall, UAC status, SMBv1 disablement, account lockout threshold, password min length.
   - Genuine scoring formula: `round((passed / (passed + failed)) * 100, 1)` (excluding NOT_APPLICABLE).
   - Zero hardcoded mock PASS values! Real evaluation with fallback error resilience.
3. Implement `SCAEngine` in `backend/app/services/sca_engine.py` & FastAPI router in `backend/app/api/v1/endpoints/sca.py`:
   - Accept `AsyncSession` database dependency.
   - Persist reports to `sca_scan_reports` table (`SCAScanReport` model).
   - Manage policies in `sca_policies` table (`SCAPolicy` model).
   - Endpoints: `POST /api/v1/sca/report`, `GET /api/v1/sca`, `GET /api/v1/sca/reports/{agent_id}`, `GET /api/v1/sca/summary`.
   - Strict tenant isolation and zero fake fallback dictionaries (empty DB returns empty list/summary).
4. Implement tests:
   - `agent/tests/test_sca_benchmarks.py`: Rule evaluators, Linux/Windows CIS checks, compliance scoring math, empty/corrupted configs, error handling.
   - `backend/tests/test_sca_engine.py`: Report ingestion, database persistence, tenant isolation, empty state zero-fake-data check, summary aggregations.
5. Verification:
   - `python -m pytest backend/tests/test_sca_engine.py agent/tests/test_sca_benchmarks.py -v`
   - `ruff check backend agent`
   - `mypy backend/app agent/arka_agent`
   - `bandit -r backend/app agent/arka_agent -ll`
6. Write `handoff.md` and send a completion message.
