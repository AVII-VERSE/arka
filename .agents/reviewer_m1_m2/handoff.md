# Review & Challenge Report: Milestones M1 & M2

**Reviewer**: `reviewer_m1_m2` (teamwork_preview_reviewer #1)  
**Roles**: Reviewer, Adversarial Critic  
**Date**: 2026-08-26  
**Scope**: 
- **Milestone M1**: Core DB Models & Schemas (`backend/app/models/models.py`, `backend/app/schemas/schemas.py`, `backend/tests/test_persistence.py`)
- **Milestone M2**: R1: Rootcheck & System Anomaly Harvester (`agent/arka_agent/collectors/rootcheck.py`, `agent/tests/test_rootcheck_and_syscollector.py`)

---

## Review Summary

**Verdict**: **APPROVE**  
**Overall Risk Assessment**: **LOW**  
**Integrity Validation**: **PASS** (Zero fake data, zero facade implementations, zero hardcoded bypasses)

---

## 1. Observation

### 1.1 Milestone M1 (Database Models & Pydantic Schemas)
1. **SQLAlchemy 2.x Declarative Models (`backend/app/models/models.py`)**:
   - Implements all 12 requested models across R2-R5 with modern typed annotations (`Mapped[...]` and `mapped_column(...)`):
     - **R2 (SCA)**: `SCAPolicy` (lines 217-230), `SCAScanReport` (lines 233-248).
     - **R3 (Syscollector Inventory)**: `AgentInventoryHardware` (lines 253-265), `AgentInventoryOS` (lines 268-280), `AgentInventoryPackage` (lines 282-293), `AgentInventoryNetwork` (lines 296-306), `AgentInventoryPort` (lines 309-321), `AgentInventoryProcess` (lines 323-335).
     - **R4 (Active Response)**: `ActiveResponseTask` (lines 340-363).
     - **R5 (Vulnerability & CVE)**: `CVEItem` (lines 368-382), `VulnerabilityFinding` (lines 384-403), `VulnerabilityScanReport` (lines 406-418).
   - Supporting enums are cleanly typed (`str, enum.Enum`): `RoleEnum`, `SeverityEnum`, `AlertStatusEnum`, `IncidentStatusEnum`, `AgentStatusEnum`, `ActiveResponseTaskStatusEnum`, `ActiveResponseActionEnum`, `VulnerabilityStatusEnum`.
   - Appropriate indexes and foreign keys are defined for `tenant_id`, `agent_id`, `user_id`, `alert_id`, `policy_id`, `cve_id`, and `package_name`. Unique constraints are enforced on `(agent_id)` for singleton hardware/OS inventory records.

2. **Pydantic v2 Schemas (`backend/app/schemas/schemas.py`)**:
   - Implements 22 request/response schemas for all entities:
     - **SCA**: `SCAPolicyBase`, `SCAPolicyCreate`, `SCAPolicyRead`, `SCACheckResult`, `SCAScanReportRead`, `SCASummary`.
     - **Inventory**: `HardwareInventoryRead`, `OSInventoryRead`, `PackageInventoryRead`, `NetworkInventoryRead`, `PortInventoryRead`, `ProcessInventoryRead`, `InventorySnapshotPayload`, `AgentInventorySummary`.
     - **Active Response**: `ActiveResponseTaskCreate`, `ActiveResponseTaskRead`, `ActiveResponseStatusUpdate`, `ActiveResponseTriggerRequest`.
     - **Vulnerability**: `CVEItemBase`, `CVEItemRead`, `VulnerabilityFindingRead`, `VulnerabilityScanReportRead`, `VulnerabilityStatusUpdate`, `VulnerabilityScanPayload`.
   - Every `Read` schema configures `model_config = ConfigDict(from_attributes=True)` matching SQLAlchemy ORM fields 1:1.

3. **Persistence & Lifecycle Tests (`backend/tests/test_persistence.py`)**:
   - Contains 12 asynchronous test functions validating DB persistence against an in-memory SQLite/aiosqlite session with `StaticPool`.
   - Covers entity relationships, foreign key integrity, JSON column serialization, status mutations, and multi-tenant boundary isolation.

### 1.2 Milestone M2 (Rootcheck Collector & Test Suite)
1. **Collector Architecture (`agent/arka_agent/collectors/rootcheck.py`)**:
   - `RootcheckScanner` correctly subclasses `BaseCollector` (`name="rootcheck"`, `enabled=enabled`) and implements `collect() -> list[dict[str, Any]]` and `run_full_scan()`.
   - Implements four primary security harvesters:
     - `scan_suspicious_files`: Scans known rootkit artifact files/dirs (Diamorphine, Reptile, Azazel, Adore-ng, Knark, t0rn, Ebury, Windows drivers/registry keys) and walks volatile directories (`/tmp`, `/var/tmp`, `/dev/shm`) for anomalous SUID/SGID binaries (`stat.S_ISUID`, `stat.S_ISGID`).
     - `scan_hidden_processes`: Performs dual-view cross-validation between `psutil.pids()` and raw `/proc/[0-9]+` entries plus POSIX `os.kill(c_pid, 0)` existence probing. Reads `/proc/<pid>/comm` and `/proc/<pid>/cmdline`.
     - `scan_listening_ports`: Inspects TCP listeners (`CONN_LISTEN`) and UDP sockets (`type=2`), flags high-risk backdoor ports (`BACKDOOR_PORTS = (31337, 6667, 4444, 12345, 65535)`), detects unmapped sockets (`pid is None`), and audits Linux promiscuous network interfaces via `/sys/class/net/<iface>/flags` with bitmask `IFF_PROMISC_FLAG = 0x100`.
     - `scan_system_binaries`: Audits dynamic linker preload tampering (`/etc/ld.so.preload` and Windows `AppInit_DLLs`), and verifies critical system binaries for existence, 0-byte truncation, and `stat.S_IWOTH` world-writable permissions.
   - All events are generated via `_build_event` conforming strictly to the `NormalizedEvent` telemetry structure with MITRE ATT&CK technique tags (`T1014`, `T1548.001`, `T1547.001`, `T1571`, `T1040`, `T1574.006`, `T1036`, `T1222`).

2. **Test Suite (`agent/tests/test_rootcheck_and_syscollector.py`)**:
   - 28 unit and integration tests covering interface compliance, artifact detection, volatile directory SUID scanning, backdoor port detection, unmapped socket detection, promiscuous flags, preload tampering, critical binary tampering/missing/permissions, clean system baseline, disabled collector behavior, dual-view hidden processes, permission denial resilience, and mid-scan process termination.

---

## 2. Logic Chain

1. **Schema & Model Consistency**:
   - Each column in `models.py` has an equivalent field in `schemas.py`.
   - The persistence tests in `test_persistence.py` instantiate SQLAlchemy ORM instances and validate them with `SchemaRead.model_validate(orm_instance)`, guaranteeing zero schema drift.

2. **Telemetry Standardization**:
   - All events produced by `RootcheckScanner` match the `NormalizedEvent` schema in `backend/app/schemas/schemas.py` (`tenant_id`, `agent_id`, `event_id`, `timestamp`, `source_type="rootcheck"`, `host`, `event_type="rootkit_detection"`, `action`, `severity`, `message`, `metadata`, `ingested_at`).

3. **Exception Resilience & Production Readiness**:
   - Every OS-level call (`open`, `os.stat`, `os.listdir`, `os.walk`, `winreg.OpenKey`, `psutil.pids`, `psutil.net_connections`, `psutil.Process`) is protected by targeted `try...except` blocks handling `PermissionError`, `psutil.AccessDenied`, `psutil.NoSuchProcess`, `psutil.ZombieProcess`, `ValueError`, and `OSError`.
   - A permission failure on a single file or PID logs a debug message and allows the scan to proceed without crashing the agent daemon.

4. **Hermetic Testability via Dependency Inversion**:
   - Scanner parameters (`suspicious_paths`, `proc_dir`, `sys_net_dir`, `preload_path`, `critical_binaries`, `suid_scan_dirs`, `custom_connections`, `known_pids`, `candidate_pids`) are configurable in `__init__` and method signatures, enabling 100% hermetic unit testing using `tmp_path` and mocks without requiring root/SYSTEM privileges.

---

## 3. Adversarial Stress-Testing & Attack Surface

### 3.1 Stress-Test Scenarios

| # | Attack / Failure Scenario | Theoretical Impact | Implementation Defense & Stress-Test Result | Status |
|---|---|---|---|---|
| 1 | **Mid-Scan Process Termination** (Process exits between `/proc` listing and reading `/proc/<pid>/cmdline`) | Unhandled `FileNotFoundError`/`OSError` crash | Handled in `scan_hidden_processes` lines 351-352 with graceful fallback (`cmdline="unknown"`). Verified in `test_process_terminated_mid_scan`. | **PASS** |
| 2 | **Corrupted Network Interface Flags** (File in `/sys/class/net/<iface>/flags` contains non-hex string) | Unhandled `ValueError` in `int(flag_content, 0)` | Handled in `scan_listening_ports` lines 502-503. Verified in `test_promiscuous_interface_corrupted_flags`. | **PASS** |
| 3 | **Access Denied on Backdoor Process** (`psutil.Process(pid)` raises `AccessDenied` or `NoSuchProcess`) | Unreported backdoor listener | `psutil.Process` instantiation is wrapped in granular try/except; port is still flagged as `suspicious_port_listening` with `process_name="unknown"`. Verified in `test_psutil_process_access_denied_on_backdoor_port`. | **PASS** |
| 4 | **SUID Scan I/O Explosion** (Walking entire root `/` filesystem for SUID binaries) | Heavy CPU & disk I/O, potential denial of service | `_get_suid_scan_dirs()` strictly scopes SUID checks to volatile world-writable directories (`/tmp`, `/var/tmp`, `/dev/shm`). | **PASS** |
| 5 | **Non-POSIX Filesystem Portability** (`chmod` / SUID not supported on NTFS / Windows) | False test failures on Windows CI | Tests gracefully check `hasattr(stat, "S_ISUID")` and use `pytest.skip` on platforms where `chmod` does not support SUID bits. | **PASS** |

### 3.2 Integrity Validation
- **No dummy or facade code**: All methods implement real OS logic (`os.stat`, `psutil`, `winreg`, `/proc`).
- **No hardcoded test outputs**: Detection criteria evaluate real inputs rather than returning fixed arrays.
- **Zero fake data**: Telemetry fields are derived from real host properties (`platform.node()`, `datetime.now(UTC)`).

---

## 4. Caveats

- **Root / Administrator Privileges in Production**: While the scanner safely handles permission denials when run by non-privileged accounts, maximum detection fidelity (e.g. reading other users' `/proc/<pid>` or raw network sockets) requires standard endpoint agent service privileges (`root` on Linux, `SYSTEM` on Windows).
- **PostgreSQL / OpenSearch Migration Integration**: The in-memory test suite uses SQLite; full multi-node PostgreSQL and OpenSearch indexing will be tested end-to-end in Milestone M7.

---

## 5. Conclusion

Milestone M1 (`backend/app/models/models.py`, `backend/app/schemas/schemas.py`, `backend/tests/test_persistence.py`) and Milestone M2 (`agent/arka_agent/collectors/rootcheck.py`, `agent/tests/test_rootcheck_and_syscollector.py`) strictly adhere to the project specifications, architectural layout, and quality standards. 

Both milestones are approved for downstream milestones (M3-M6).

---

## 6. Verification Method

To independently verify M1 and M2:

1. **Run Backend Persistence Tests**:
   ```bash
   python -m pytest backend/tests/test_persistence.py -v
   ```
2. **Run Rootcheck & Agent Tests**:
   ```bash
   python -m pytest agent/tests/test_rootcheck_and_syscollector.py -v
   ```
3. **Run Static Analysis & Linters**:
   ```bash
   ruff check backend/app agent/arka_agent
   mypy backend/app agent/arka_agent
   bandit -r backend/app agent/arka_agent -ll
   ```
