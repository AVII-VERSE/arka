## 2026-08-27T04:46:00Z
<USER_REQUEST>
You are teamwork_preview_worker #5 for Milestone M5 (R4: Automated Active Response Container & Backend Service).

Your Working Directory: d:/ARKA/.agents/worker_m5
Original Request Path: d:/ARKA/.agents/ORIGINAL_REQUEST.md
Project Scope Document: d:/ARKA/PROJECT.md
Survey Reference: d:/ARKA/.agents/explorer_survey_1/handoff.md § 4.5 and d:/ARKA/.agents/explorer_survey_2/handoff.md § 2.1

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Scope & Exclusively Owned Files:
- `agent/arka_agent/active_response.py`
- `backend/app/services/active_response_service.py`
- `backend/app/api/v1/endpoints/active_response.py`
- `agent/tests/test_active_response.py`
- `backend/tests/test_active_response_service.py`

Tasks:
1. Initialize `progress.md` and `BRIEFING.md` in `d:/ARKA/.agents/worker_m5`.
2. Implement `ActiveResponseExecutor` in `agent/arka_agent/active_response.py`:
   - Real firewall IP blocking (`block_ip` / `unblock_ip`): `iptables` command generation on Linux, `netsh advfirewall` on Windows.
   - Strict IP allowlist protection: Disallow blocking `127.0.0.1`, `::1`, `127.0.0.0/8`, `255.255.255.255`, default gateway, or backend host.
   - Safe process termination (`kill_process`): Two-phase terminate (`SIGTERM`) -> wait up to 3.0s -> force kill (`SIGKILL`). Strict protected PID allowlist: PID 0, 1, 2, 4, `smss.exe`, `csrss.exe`, `wininit.exe`, `services.exe`, `lsass.exe`, and agent daemon PID.
   - Secure file quarantine vault (`quarantine_file` / `unquarantine_file`): Unique hash identifier, manifest creation (`<sha256>.manifest.json`), permissions preservation, and restore.
   - Execution timeout (default 15s), automated rollback timers (`duration_seconds`), comprehensive audit logging dictionaries.
3. Implement `ActiveResponseService` in `backend/app/services/active_response_service.py` & router in `backend/app/api/v1/endpoints/active_response.py`:
   - Accept `AsyncSession` database dependency.
   - Task lifecycle state machine: `PENDING` -> `DISPATCHED` -> `EXECUTING` -> `SUCCESS` / `FAILED` / `TIMEOUT` in `active_response_tasks` table (`ActiveResponseTask` model).
   - Target safety validation before dispatching.
   - Automated response dispatch on `CRITICAL` or `BRUTE_FORCE_LOGIN` alerts.
   - Agent task poll endpoint `GET /api/v1/active_response/agents/{agent_id}/pending` and execution callback `POST /api/v1/active_response/tasks/{task_id}/result`.
   - Endpoints: `POST /api/v1/active_response/trigger`, `GET /api/v1/active_response/tasks`, `GET /api/v1/active_response/tasks/{task_id}`, `POST /api/v1/active_response/tasks/{task_id}/result`.
   - Real `AuditLog` creation in `audit_logs` table.
   - Zero fake fallback logs (empty DB returns empty list `[]`).
4. Implement tests:
   - `agent/tests/test_active_response.py`: IP block/unblock, safe process kill, system PID safety protection, quarantine/unquarantine cycle with `tmp_path`, execution timeouts, and audit trail generation.
   - `backend/tests/test_active_response_service.py`: Task lifecycle, automated alert trigger, manual trigger, IP/PID safety whitelist guards, agent task callback, audit trail generation, zero-fake-data empty state.
5. Verification:
   - `python -m pytest backend/tests/test_active_response_service.py agent/tests/test_active_response.py -v`
   - `ruff check backend agent`
   - `mypy backend/app agent/arka_agent`
   - `bandit -r backend/app agent/arka_agent -ll`
6. Write `handoff.md` and send a completion message.
</USER_REQUEST>
