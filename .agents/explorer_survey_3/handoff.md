# Test Infrastructure, Quality & CI Tooling Survey Report
**ARKA Enterprise SIEM & XDR Platform**

---

## 1. Observation

### 1.1 Tooling & Environment Configuration
- **Virtual Environment**: Located at `d:\ARKA\backend\.venv` with Python 3.13.14 runtime.
- **Editable Package Installs**:
  - `arka-backend` (`0.1.0`) installed in editable mode from `d:\ARKA\backend`.
  - `arka-agent` (`0.1.0`) installed in editable mode from `d:\ARKA\agent`.
- **Core Tooling Versions**:
  - `pytest`: 9.1.1 (`pytest-asyncio` 1.4.0, `pytest-cov` 7.1.0)
  - `ruff`: 0.16.3
  - `mypy`: 2.3.1
  - `bandit`: 1.9.4
  - `pip-audit`: 2.10.1
- **Configuration Files**:
  - `backend/pyproject.toml`:
    - `[tool.pytest.ini_options]`: `minversion = "8.0"`, `addopts = "-ra -q --strict-markers"`, `testpaths = ["tests"]`, `asyncio_mode = "auto"` (lines 70-75).
    - `[tool.ruff.lint]`: `select = ["E", "F", "B", "I", "N", "UP", "PL"]`, `ignore = ["E501", "PLR2004", "PLR0913", "PLR0917", "BLE001", "S110", "UP042"]`, `line-length = 100` (lines 53-59).
    - `[tool.mypy]`: `python_version = "3.12"`, `ignore_missing_imports = true` with overrides for `yaml.*`, `jose.*`, `passlib.*`, `structlog.*` (lines 61-69).
  - `agent/pyproject.toml`:
    - `[tool.pytest.ini_options]`: `minversion = "8.0"`, `addopts = "-ra -q"`, `testpaths = ["tests"]` (lines 40-44).
    - `[tool.ruff.lint]`: `select = ["E", "F", "B", "I", "N", "UP", "PL"]`, `ignore = ["E501", "PLR2004", "PLR0913", "PLR0917", "BLE001", "S110", "UP042"]` (lines 36-39).

### 1.2 Existing Test Suite Execution & Baseline Results
Running pytest against both `backend/tests` and `agent/tests` produces **31 passed tests out of 31 collected (100% pass rate in 2.10s)**:
- **Backend Tests (`backend/tests/` - 17 tests passed in 0.96s)**:
  - `test_auth.py` (3 tests): `test_register_tenant`, `test_user_login_and_me`, `test_invalid_login`.
  - `test_events.py` (1 test): `test_event_ingestion_and_list`.
  - `test_health.py` (3 tests): `test_healthz`, `test_readyz`, `test_livez`.
  - `test_kafka_pipeline.py` (3 tests): `test_kafka_producer_publish_and_retrieve`, `test_kafka_consumer_normalization`, `test_kafka_dlq_malformed_event_routing`.
  - `test_opensearch_service.py` (3 tests): `test_opensearch_index_naming_pattern`, `test_opensearch_ecs_mapping_structure`, `test_opensearch_indexing_and_search_query`.
  - `test_persistence.py` (4 tests): `test_alert_persistence_and_status_mutation`, `test_incident_persistence`, `test_agent_enrollment_persistence`, `test_tenant_isolation_boundary`.
- **Agent Tests (`agent/tests/` - 14 tests passed in 0.81s)**:
  - `test_active_response.py` (2 tests): `test_active_response_executor`, `test_active_response_service_dispatch`.
  - `test_collectors.py` (2 tests): `test_windows_collector`, `test_linux_collector`.
  - `test_fim_and_process_lineage.py` (3 tests): `test_fim_baseline_and_modification_detection`, `test_fim_file_deletion_detection`, `test_process_lineage_metadata_schema`.
  - `test_queue.py` (1 test): `test_sqlite_queue_push_pop`.
  - `test_rootcheck_and_syscollector.py` (2 tests): `test_rootcheck_scanner_execution`, `test_syscollector_inventory_harvesting`.
  - `test_sca_benchmarks.py` (2 tests): `test_sca_scanner_execution`, `test_sca_engine_aggregation`.
  - `test_vulnerability_engine.py` (2 tests): `test_package_vulnerability_scanner`, `test_vulnerability_engine_correlation`.

### 1.3 Test Fixtures & Infrastructure
- **Backend Fixtures in `backend/tests/conftest.py`**:
  - `TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"`: Isolated in-memory async SQLite engine.
  - `db_session`: Async fixture handling automated schema creation (`Base.metadata.create_all`) and teardown (`drop_all`).
  - `client`: `AsyncClient` fixture binding `ASGITransport(app=app)` with `app.dependency_overrides[get_db]`.
  - `test_tenant`: Persisted `Tenant` record with `name="Test CyberCorp"` and `slug="test-cybercorp"`.
  - `test_user`: Persisted `User` record with role `SECURITY_ANALYST` and bcrypt-hashed password.
  - `auth_headers`: Returns JWT bearer authentication header `{"Authorization": f"Bearer {token}"}`.
- **In-Memory Service Stores** (Require per-test reset/isolation):
  - `_SCA_REPORT_STORE` in `backend/app/services/sca_engine.py:7`
  - `_INVENTORY_STORE` in `backend/app/api/v1/endpoints/inventory.py:18`
  - `_ACTIVE_RESPONSE_LOGS` in `backend/app/services/active_response_service.py:8`
  - `_VULNERABILITY_REPORTS` in `backend/app/services/vulnerability_engine.py:48`
- **Agent Collector Fixtures**:
  - Pytest `tmp_path` fixture utilized for filesystem isolation (FIM baseline checks, SQLite queue persistence).

---

## 2. Logic Chain & Analysis

1. **Test Infrastructure Readiness**:
   - The test foundation is exceptionally fast (<2.2s for the complete suite) because of in-memory async SQLite engines, mock Kafka buffers, and lightweight in-memory OpenSearch structures.
   - Both `arka-backend` and `arka-agent` are linked in editable mode, allowing cross-package integration tests without separate installation steps.

2. **Existing Coverage vs Requirement Scope (R1-R5)**:
   - While initial baseline tests exist for R1-R5 (2 tests each in `agent/tests`), they only verify the happy path with 1-2 basic assertions.
   - None of the REST API endpoints (`/api/v1/inventory`, `/api/v1/sca`, `/api/v1/active-response`, `/api/v1/vulnerabilities`) currently have direct HTTP client integration tests in `backend/tests/`.
   - Comprehensive testing requires multi-tiered validation: unit feature tests, edge/corner cases, cross-feature pipelines, and realistic attack simulations.

3. **Formulated 4-Tier Test Strategy**:

### Tier 1: Core Feature Coverage (>=5 test cases per requirement, total >=25 tests)

#### R1: Rootcheck & System Anomaly Harvester (`agent/arka_agent/collectors/rootcheck.py`)
1. `test_rootcheck_suspicious_files_detection`: Verifies detection of planted rootkit artifact files across platform-specific locations (`.hidden`, `.rootkit`).
2. `test_rootcheck_suspicious_ports_detection`: Verifies detection of backdoor/unmapped listening sockets (ports `31337`, `6667`, `4444`) with PID and process name resolution.
3. `test_rootcheck_clean_state_zero_findings`: Verifies scanner returns empty findings on a clean system without false positives.
4. `test_rootcheck_full_audit_scan_aggregation`: Verifies `run_full_scan()` aggregates both filesystem and network socket anomalies with standard ECS metadata.
5. `test_rootcheck_platform_path_dispatch`: Verifies Windows vs Linux suspicious path resolution (`System32\drivers\etc` vs `/dev/.static`, `/var/tmp/.rootkit`).

#### R2: Security Configuration Assessment (SCA) & CIS Benchmarks Engine (`agent/arka_agent/collectors/sca.py`, `backend/app/services/sca_engine.py`, `backend/app/api/v1/endpoints/sca.py`)
1. `test_sca_ssh_root_login_check`: Evaluates SSH `PermitRootLogin` config parsing (`PASS` when "PermitRootLogin no", `FAIL` when enabled, `NOT_APPLICABLE` on Windows).
2. `test_sca_host_firewall_check`: Verifies firewall status evaluation across Windows (`netsh advfirewall`) and Linux (`ufw`/`iptables`).
3. `test_sca_password_policy_check`: Validates password complexity policy evaluation (14+ character enforcement).
4. `test_sca_compliance_scoring_algorithm`: Validates mathematical formula `round(pass_count / total_scanned * 100, 1)` across various pass/fail distributions.
5. `test_sca_backend_api_ingest_and_list`: Validates `/api/v1/sca/report` POST ingestion and `/api/v1/sca` GET listing with tenant isolation.

#### R3: Syscollector System Inventory Harvester (`agent/arka_agent/collectors/syscollector.py`, `backend/app/api/v1/endpoints/inventory.py`)
1. `test_syscollector_hardware_inventory`: Validates CPU logical/physical core counts, RAM total/available/used percentages, and disk partition stats.
2. `test_syscollector_os_metadata_harvesting`: Validates OS name, release, kernel version, hostname, and python version extraction.
3. `test_syscollector_network_interfaces_parsing`: Validates IPv4, IPv6, and MAC address resolution across active adapters.
4. `test_syscollector_running_processes_harvesting`: Validates process table enumeration, PID, name, user, CPU/RAM metrics, and limit truncation.
5. `test_syscollector_inventory_rest_api`: Validates `/api/v1/inventory/snapshot` POST and authenticated `/api/v1/inventory` GET retrieval.

#### R4: Automated Active Response Container (`agent/arka_agent/active_response.py`, `backend/app/services/active_response_service.py`, `backend/app/api/v1/endpoints/active_response.py`)
1. `test_active_response_block_ip`: Validates IP firewall blocking execution, response structure, and target logging.
2. `test_active_response_kill_process_active`: Validates process termination on active PIDs via psutil.
3. `test_active_response_kill_process_nonexistent`: Validates graceful `NOT_FOUND` status when targeting non-existent or exited PIDs.
4. `test_active_response_quarantine_directory_creation`: Validates creation and path resolution of OS-specific quarantine folder (`C:\ARKA_Quarantine` vs `/var/lib/arka/quarantine`).
5. `test_active_response_backend_dispatch_and_api`: Validates automated trigger on CRITICAL/HIGH alerts and manual `/api/v1/active-response/trigger` endpoint.

#### R5: Vulnerability Detection & CVE Correlation Engine (`backend/app/services/vulnerability_engine.py`, `agent/arka_agent/collectors/vulnerability.py`, `backend/app/api/v1/endpoints/vulnerabilities.py`)
1. `test_vulnerability_scanner_package_collection`: Validates software package inventory extraction from agent environment.
2. `test_vulnerability_engine_cve_correlation`: Validates package name and vulnerable version matching against NVD CVE database (e.g. `log4j 2.14.1` -> `CVE-2021-44228`).
3. `test_vulnerability_engine_severity_metrics`: Validates CVSS score aggregation, `critical_count`, `high_count`, and `medium_count` tallies.
4. `test_vulnerability_engine_remediation_advisories`: Validates CVE remediation summary and fixed version recommendations (`fixed_version`).
5. `test_vulnerability_rest_api_scan_and_query`: Validates `/api/v1/vulnerabilities/scan` POST and `/api/v1/vulnerabilities` GET retrieval per tenant.

---

### Tier 2: Boundary, Fault Injection, Edge & Corner Cases (>=5 test cases per requirement, total >=25 tests)

#### R1 Corner Cases:
1. `test_rootcheck_permission_denied_filesystem`: Scanner handles inaccessible/permission-denied folders without throwing unhandled exceptions.
2. `test_rootcheck_process_terminated_mid_scan`: Handles `NoSuchProcess` or `AccessDenied` during socket-to-process PID resolution.
3. `test_rootcheck_empty_suspicious_paths_list`: Verifies clean scan execution when custom suspicious path list is empty.
4. `test_rootcheck_ipv6_and_ephemeral_ports`: Handles IPv6 dual-stack sockets and unusual high port numbers.
5. `test_rootcheck_timestamp_uniqueness_and_precision`: Verifies rapid successive scans produce unique ISO-8601 timestamps and distinct event IDs.

#### R2 Corner Cases:
1. `test_sca_all_checks_not_applicable`: Verifies compliance score defaults to `100.0%` when `total_scanned == 0` (no applicable rules).
2. `test_sca_all_checks_failing`: Verifies compliance score is `0.0%` when all audited rules fail.
3. `test_sca_corrupted_sshd_config_file`: Gracefully handles unreadable, empty, or binary sshd config files without crash.
4. `test_sca_subprocess_timeout_on_firewall`: Subprocess timeout during `netsh` or `ufw` execution falls back gracefully.
5. `test_sca_duplicate_agent_report_overwrites`: Backend updates existing agent's report rather than duplicating entries in store.

#### R3 Corner Cases:
1. `test_syscollector_virtual_memory_zero_or_overflow`: Handles mock zero total memory without division by zero.
2. `test_syscollector_process_access_denied`: Handles system-level processes (e.g. PID 0, PID 4, kernel threads) where info lookup raises `AccessDenied`.
3. `test_syscollector_inaccessible_disk_partitions`: Handles raw/unmounted or virtual disk partitions where `disk_usage` raises `OSError`.
4. `test_syscollector_interfaces_without_ip_or_mac`: Handles loopback or virtual network interfaces missing IPv4/IPv6/MAC addresses.
5. `test_syscollector_process_limit_enforcement`: Verifies process table correctly truncates when system has hundreds of processes.

#### R4 Corner Cases:
1. `test_active_response_invalid_ip_format`: Handles malformed or non-routable IP strings securely.
2. `test_active_response_kill_protected_system_pid`: Gracefully handles permission failures when attempting to kill protected system processes (PID 1 / System).
3. `test_active_response_unsupported_action_command`: Handles unknown command names with safe custom action fallback.
4. `test_active_response_low_severity_no_trigger`: Ensures LOW and MEDIUM alerts do NOT trigger automated containment.
5. `test_active_response_quarantine_disk_full`: Handles `OSError` during quarantine directory creation or file movement.

#### R5 Corner Cases:
1. `test_vulnerability_engine_empty_packages_list`: Returns 0 vulnerabilities and 0 counts when package inventory is empty.
2. `test_vulnerability_engine_patched_versions`: Verifies patched package versions (`log4j 2.17.1`, `openssl 1.1.1u`) produce 0 CVE findings.
3. `test_vulnerability_engine_case_insensitive_matching`: Matches "Log4J", "OpenSSL", "CURL" regardless of letter casing.
4. `test_vulnerability_engine_unknown_packages`: Ignores proprietary/untracked packages without error.
5. `test_vulnerability_engine_multiple_cves_single_package`: Accurately reports multiple CVEs impacting the same package version.

---

### Tier 3: Cross-Feature Interactions & End-to-End Pipeline Tests (>=5 tests)

1. `test_pipeline_syscollector_to_vulnerability_engine_e2e`: Syscollector harvests software inventory -> passes directly to `/api/v1/vulnerabilities/scan` -> correlates CVEs -> validates output report.
2. `test_pipeline_rootcheck_anomaly_to_active_response_containment`: Rootcheck detects rootkit backdoor socket -> generates CRITICAL alert -> ActiveResponseService triggers IP block and process kill -> verifies audit trail.
3. `test_pipeline_sca_benchmark_compliance_dashboard_sync`: SCA agent reports CIS benchmark compliance -> backend updates tenant metrics -> analyst queries `/api/v1/sca` and receives aggregated compliance posture.
4. `test_pipeline_agent_telemetry_batch_ingest_kafka_opensearch`: Syscollector + Rootcheck events buffered in SQLiteQueue -> Transport flushes batch to `/api/v1/events/ingest` -> Kafka consumer normalizes -> OpenSearch indexes with ECS mapping.
5. `test_pipeline_multi_tenant_isolation_across_all_modules`: Simultaneous submission of inventory, SCA, vulnerability, and active response data across Tenant A and Tenant B; verifies strict isolation across all REST endpoints.

---

### Tier 4: Real-World SIEM / XDR Attack & Incident Scenarios (>=5 tests)

1. **Scenario 1: Log4Shell RCE Exploitation & Automated Containment (CVE-2021-44228)**:
   - Vulnerability engine detects vulnerable `log4j 2.14.1`.
   - Attacker initiates exploit -> FIM detects unauthorized binary drop, process lineage detects child `powershell.exe`.
   - Alert generated (CRITICAL) -> ActiveResponse blocks attacker IP `198.51.100.42` and terminates malicious process.
2. **Scenario 2: Rootkit Persistence & Backdoor C2 Communication**:
   - Rootcheck scanner identifies hidden kernel driver `.hidden` and active backdoor listening on port `31337`.
   - Threat alert created in PostgreSQL -> Active response quarantines artifact and terminates backdoor PID.
3. **Scenario 3: CIS Benchmark Configuration Drift & Privilege Escalation (CVE-2021-3156)**:
   - SCA audit discovers SSH root login enabled and weak password policy (Compliance score drops to 33.3%).
   - Vulnerability engine flags vulnerable `sudo 1.9.5p2` (Baron Samedit).
   - High-priority security incident generated for analyst triage.
4. **Scenario 4: High-Volume Endpoint Brute Force Attack**:
   - Ingestion of repeated failed authentication events (Event Code 4625) from IP `203.0.113.88`.
   - Detection rule `BRUTE_FORCE_LOGIN` triggers -> Automated Active Response immediately blocks offending IP at the firewall.
5. **Scenario 5: Agent Offline Buffering & Resilient Re-synchronization**:
   - Agent operates during network outage, buffering Syscollector, SCA, and Rootcheck telemetry in SQLiteQueue.
   - Network connectivity restored -> Agent flushes FIFO queue to backend -> All records ingested without loss or corruption.

---

## 3. Caveats & Assumptions

- **In-Memory Store Isolation**: Backend services (`SCAEngine`, `VulnerabilityEngine`, `ActiveResponseService`, `_INVENTORY_STORE`) use in-memory module-level dictionaries. Tests modifying these stores must either mock them or provide teardown fixtures to prevent cross-test state leakage.
- **Platform-Dependent Tests**: OS-specific collectors (`windows_event_log.py`, `linux_syslog.py`, `netsh` vs `ufw`) should use mock fixtures when executing in heterogeneous CI environments (e.g. Linux CI runner vs Windows local development).
- **No Direct Implementation**: In accordance with explorer role guidelines, no source code was modified during this survey.

---

## 4. Conclusion

1. **Test Infrastructure Health**: The existing test runner and quality tooling (`pytest`, `ruff`, `mypy`, `bandit`) are properly configured and operational via the `d:\ARKA\backend\.venv` environment.
2. **Current Baseline**: 31 existing tests pass cleanly (100% pass rate in ~2.1s).
3. **Actionable Roadmap**: The 4-Tier test strategy outlined in this report provides complete coverage across all 5 requirements (R1-R5), expanding test coverage from 31 baseline tests to >90 comprehensive tests covering unit, edge, cross-feature, and SIEM attack scenarios.

---

## 5. Verification Method

To independently reproduce and verify this survey:

1. **Execute Pytest Suite**:
   ```powershell
   & "d:\ARKA\backend\.venv\Scripts\pytest.exe" backend/tests agent/tests -v
   ```
2. **Execute Ruff Lint Check**:
   ```powershell
   & "d:\ARKA\backend\.venv\Scripts\ruff.exe" check backend agent
   ```
3. **Execute Mypy Type Check**:
   ```powershell
   & "d:\ARKA\backend\.venv\Scripts\mypy.exe" backend app agent/arka_agent
   ```
4. **Execute Bandit Security Scan**:
   ```powershell
   & "d:\ARKA\backend\.venv\Scripts\bandit.exe" -r backend/app agent/arka_agent -ll
   ```
5. **Inspect Test Configurations**:
   - View `backend/pyproject.toml` (lines 53-75)
   - View `agent/pyproject.toml` (lines 36-44)
   - View `backend/tests/conftest.py` (lines 1-83)
