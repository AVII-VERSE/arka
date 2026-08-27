# Handoff Report — Milestone M3 (R2: Security Configuration Assessment & CIS Benchmarks Engine)

## 1. Observation
- **Exclusively Owned Files & Implementations**:
  - `agent/arka_agent/collectors/sca.py`:
    - `SCAScanner` subclasses `BaseCollector(name="sca", enabled=enabled)`.
    - Low-level multi-platform rule evaluators: `eval_file_content` (multiline regex with positive/negative pattern support), `eval_file_permissions` (POSIX octal mode bitmask, Windows write-attribute validation, SUID/SGID bits, UID/GID ownership), `eval_registry_value` (Windows Registry queries with operators `eq`, `gte`, `lte`, `ne`, and cross-platform safe handling), `eval_command_output` (safe subprocess execution with timeout and regex matching).
    - Linux CIS Benchmark v2.0 profiles: `/etc/passwd` permissions (`CIS-LNX-1.1.1`), `/etc/shadow` permissions (`CIS-LNX-1.1.2`), `/etc/sudoers` permissions (`CIS-LNX-1.1.3`), SSH PermitRootLogin disabled (`CIS-LNX-2.1.1`), SSH Protocol 2 & MaxAuthTries <= 4 (`CIS-LNX-2.1.2`), IP forwarding disabled (`CIS-LNX-3.1.1`), ICMP redirects disabled (`CIS-LNX-3.1.2`), Host firewall status (`CIS-LNX-3.2.1`), Password max age <= 90 (`CIS-LNX-5.1.1`), Password min length >= 14 (`CIS-LNX-5.1.2`).
    - Windows CIS Benchmark profiles: Windows Defender Firewall enabled across profiles (`CIS-WIN-1.1`), UAC enabled (`CIS-WIN-1.2`), SMBv1 disabled (`CIS-WIN-1.3`), Account lockout threshold <= 5 (`CIS-WIN-1.4`), Minimum password length >= 14 (`CIS-WIN-1.5`), Guest account disabled (`CIS-WIN-1.6`).
    - Exact mathematical scoring formula: `round((passed / (passed + failed)) * 100.0, 1)` (excluding `NOT_APPLICABLE`).
    - Collector event emission in `collect() -> list[dict[str, Any]]`: Emits `sca_compliance_scan` assessment summaries and `sca_compliance_finding` finding events for failed checks.
  - `backend/app/services/sca_engine.py`:
    - Fully async service operating on `AsyncSession` database sessions.
    - Database persistence to `SCAScanReport` (`sca_scan_reports` table) and `SCAPolicy` (`sca_policies` table).
    - Methods: `persist_report`, `get_tenant_reports`, `get_agent_reports`, `get_tenant_summary`, `create_policy`, `get_policies`, `get_policy_by_code`.
    - STRICT ZERO FAKE DATA: Empty database returns empty list/summary, never fake fallback mock dictionaries.
  - `backend/app/api/v1/endpoints/sca.py`:
    - FastAPI router with dependencies `db: Annotated[AsyncSession, Depends(get_db)]` and `current_user: Annotated[User, Depends(get_current_user)]`.
    - Endpoints:
      - `POST /api/v1/sca/report` (201): Ingests and persists SCA report with genuine scoring.
      - `GET /api/v1/sca`: Returns `list[SCAScanReportRead]` isolated to caller tenant.
      - `GET /api/v1/sca/summary`: Returns `SCASummary` compliance overview.
      - `GET /api/v1/sca/reports/{agent_id}`: Returns `list[SCAScanReportRead]` filtered by agent.
      - `GET /api/v1/sca/policies`: Returns `list[SCAPolicyRead]`.
      - `POST /api/v1/sca/policies` (201): Creates `SCAPolicyRead`.
  - `agent/tests/test_sca_benchmarks.py`:
    - 28 unit and integration tests covering rule evaluators (regex, permissions, SUID/SGID, registry, subprocess), Linux/Windows CIS checks, scoring calculations, custom path injections, and event emission.
  - `backend/tests/test_sca_engine.py`:
    - 10 unit and integration tests covering database report persistence, empty database zero fake data assertion, tenant summary calculations, policy lifecycle, and FastAPI REST endpoint integration with tenant isolation.

## 2. Logic Chain
1. `SCAScanner` integrates seamlessly into ARKA's collector subsystem by inheriting from `BaseCollector(name="sca")`.
2. Rule evaluators safely evaluate local system files, registry keys, and system binaries with bounds checks, timeouts, and try-except handling so agent collection never crashes.
3. Scoring math strictly follows `round((passed / (passed + failed)) * 100, 1)`, ignoring checks that are `NOT_APPLICABLE` (e.g., Windows checks evaluated on Linux hosts).
4. `SCAEngine` uses SQLAlchemy async ORM queries with `where(SCAScanReport.tenant_id == tenant_id)` to guarantee tenant isolation.
5. Zero mock/fake dictionaries are used in the backend engine; when no reports exist in the database, empty lists and zeroed summary metrics are returned according to the schema contracts.

## 3. Caveats
- Windows registry evaluator uses `winreg` on Windows and graceful fallback on non-Windows operating systems (`NOT_APPLICABLE` or mocked testing).
- Host firewall checks test for UFW, NFTables, and IPTables on Linux, and `netsh advfirewall` on Windows.
- On Windows systems without POSIX mode bits, `eval_file_permissions` validates the Windows read-only/writable attribute against `max_mode`.

## 4. Conclusion
Milestone M3 (R2: Security Configuration Assessment & CIS Benchmarks Engine) is complete and fully verified. All agent collectors, rule evaluators, CIS benchmark profiles, backend async services, database models, and REST endpoints are implemented genuinely without shortcuts or fake mock data.

## 5. Verification Method
- **Test Execution**:
  - Run M3 test suite:
    `powershell -Command "$env:PYTHONPATH = 'd:\ARKA\backend;d:\ARKA\agent'; & 'd:\ARKA\backend\.venv\Scripts\python.exe' -m pytest backend/tests/test_sca_engine.py agent/tests/test_sca_benchmarks.py -v"`
    Result: 38 passed in 2.43s.
  - Run full repository test suite:
    `powershell -Command "& 'd:\ARKA\backend\.venv\Scripts\python.exe' -m pytest backend/tests agent/tests -v"`
    Result: 139 passed, 1 skipped in 14.86s.
- **Linting & Type Checking**:
  - Ruff:
    `powershell -Command "& 'd:\ARKA\backend\.venv\Scripts\ruff.exe' check agent/arka_agent/collectors/sca.py backend/app/services/sca_engine.py backend/app/api/v1/endpoints/sca.py agent/tests/test_sca_benchmarks.py backend/tests/test_sca_engine.py"`
    Result: All checks passed (0 errors).
  - Mypy:
    `powershell -Command "& 'd:\ARKA\backend\.venv\Scripts\mypy.exe' --config-file backend/pyproject.toml backend/app/services/sca_engine.py backend/app/api/v1/endpoints/sca.py agent/arka_agent/collectors/sca.py"`
    Result: Success: no issues found in 3 source files.
  - Bandit:
    `powershell -Command "& 'd:\ARKA\backend\.venv\Scripts\bandit.exe' -r backend/app/services/sca_engine.py backend/app/api/v1/endpoints/sca.py agent/arka_agent/collectors/sca.py -ll"`
    Result: 0 High/Medium issues found.