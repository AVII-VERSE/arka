# Forensic Audit Report — Milestones M1 & M2

**Work Product**: Milestones M1 (`backend/app/models/models.py`, `backend/app/schemas/schemas.py`) and M2 (`agent/arka_agent/collectors/rootcheck.py`, `agent/tests/test_rootcheck_and_syscollector.py`)  
**Profile**: General Project  
**Integrity Mode**: Demo / Development (with Zero-Fake-Data Enforcement)  
**Verdict**: **CLEAN**

---

## 1. Observation

### A. Milestone M1: Core Database Models (`backend/app/models/models.py`)
Direct source inspection of `backend/app/models/models.py` (lines 1 to 419) confirms full implementation of all 12 required SQLAlchemy 2.x declarative models spanning requirements R2 through R5, alongside the 7 foundational platform models:
1. **R2 (SCA)**:
   - `SCAPolicy` (lines 217-230): `policy_code`, `os_type`, `rules_count`, `enabled`, foreign key to `tenants.id`.
   - `SCAScanReport` (lines 232-248): `compliance_score`, `total_checks`, `passed_checks`, `failed_checks`, `checks` (JSON array of check objects), foreign keys to `tenants.id` and `agents.id`.
2. **R3 (Syscollector System Inventory)**:
   - `AgentInventoryHardware` (lines 253-265): `cpu_cores_logical`, `cpu_cores_physical`, `cpu_architecture`, `ram_total_gb`, `disks` (JSON).
   - `AgentInventoryOS` (lines 267-280): `os_name`, `os_release`, `os_version`, `kernel_architecture`, `hostname`, `python_version`.
   - `AgentInventoryPackage` (lines 282-293): `name`, `version`, `format`, `architecture`.
   - `AgentInventoryNetwork` (lines 295-306): `interface_name`, `ipv4_address`, `ipv6_address`, `mac_address`.
   - `AgentInventoryPort` (lines 308-321): `protocol`, `local_ip`, `local_port`, `pid`, `process_name`, `state`.
   - `AgentInventoryProcess` (lines 323-335): `pid`, `name`, `username`, `cpu_percent`, `memory_percent`.
3. **R4 (Automated Active Response)**:
   - `ActiveResponseTask` (lines 340-363): `action` (`ActiveResponseActionEnum`), `target`, `parameters` (JSON), `status` (`ActiveResponseTaskStatusEnum`), `exit_code`, `stdout`, `stderr`, `message`, `command_payload`, timestamps.
4. **R5 (Vulnerability Detection & CVE Correlation)**:
   - `CVEItem` (lines 368-382): `cve_id`, `package_name`, `affected_versions_spec`, `fixed_version`, `severity`, `cvss_score`, `cvss_vector`, `summary`, `references`.
   - `VulnerabilityFinding` (lines 384-403): `cve_id`, `package_name`, `installed_version`, `fixed_version`, `severity`, `cvss_score`, `status` (`VulnerabilityStatusEnum`), lifecycle timestamps.
   - `VulnerabilityScanReport` (lines 405-418): `scanned_packages_count`, `vulnerability_count`, `critical_count`, `high_count`, `medium_count`, `low_count`.

All models utilize standard SQLAlchemy 2.0 type mapping (`Mapped[T] = mapped_column(...)`), proper `ForeignKey` constraints with indexes, default UUID generators, and UTC timestamps. Zero mock tables, fake fields, or facade classes exist.

### B. Milestone M1: Request & Response Schemas (`backend/app/schemas/schemas.py`)
Direct source inspection of `backend/app/schemas/schemas.py` (lines 1 to 520) reveals complete Pydantic v2 schemas:
- `ConfigDict(from_attributes=True)` is configured across all ORM read schemas (`SCAPolicyRead`, `SCAScanReportRead`, `HardwareInventoryRead`, `OSInventoryRead`, `PackageInventoryRead`, `NetworkInventoryRead`, `PortInventoryRead`, `ProcessInventoryRead`, `ActiveResponseTaskRead`, `CVEItemRead`, `VulnerabilityFindingRead`, `VulnerabilityScanReportRead`).
- Request schemas (`ActiveResponseTaskCreate`, `ActiveResponseTriggerRequest`, `ActiveResponseStatusUpdate`, `InventorySnapshotPayload`, `VulnerabilityScanPayload`, `VulnerabilityStatusUpdate`) have strict type validation, field defaults, and enum bindings.
- Zero hardcoded mock responses or dummy schemas detected.

### C. Milestone M2: Rootcheck Anomaly Harvester (`agent/arka_agent/collectors/rootcheck.py`)
Direct inspection of `agent/arka_agent/collectors/rootcheck.py` (lines 1 to 682) reveals authentic security scanning logic:
- `scan_suspicious_files()`: Directly queries filesystem via `os.path.exists`, `os.path.isdir`, and `os.stat` across known rootkit artifact paths (e.g. `/dev/diamorphine`, `/dev/reptile`, `/etc/reptile`, `/lib/libcrypt.so.2`, Windows driver paths); audits volatile directories (`/tmp`, `/var/tmp`, `/dev/shm`) for SUID/SGID binaries using `stat.S_ISUID` and `stat.S_ISGID`; audits Windows registry startup keys using `winreg` (`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, `RunOnce`, `Winlogon`).
- `scan_hidden_processes()`: Performs dual-view cross-validation between `psutil.pids()` and direct `/proc` directory traversal (`os.listdir(self.proc_dir)` filtering `entry.isdigit()`) as well as POSIX signal probing `os.kill(c_pid, 0)` to detect unmapped or stealth kernel processes.
- `scan_listening_ports()`: Queries `psutil.net_connections(kind="inet")` to detect listening sockets mapped to `BACKDOOR_PORTS` (31337, 6667, 4444, 12345, 65535) and unmapped sockets where `pid is None or pid == 0`; checks Linux network interface flags in `/sys/class/net/<iface>/flags` for promiscuous mode `IFF_PROMISC` (0x100).
- `scan_system_binaries()`: Parses dynamic linker preload file `/etc/ld.so.preload` for injected shared libraries; audits Windows `AppInit_DLLs` registry key; verifies critical system binaries for existence, 0-byte truncation, and `stat.S_IWOTH` world-writable permissions.
- Normalization: Produces standardized event dictionaries matching ARKA telemetry schema.

### D. Test Suite Integrity (`agent/tests/test_rootcheck_and_syscollector.py`, `backend/tests/test_persistence.py`)
- Unit and integration tests in `test_rootcheck_and_syscollector.py` construct realistic scenarios using `pytest` fixtures (`tmp_path`), real file/dir creation, bitmask manipulation, and mock socket connection structures without self-certifying or checking hardcoded static strings.
- Persistence tests in `backend/tests/test_persistence.py` run against an async SQLite in-memory engine and verify all 12 models and schemas across CRUD operations, status mutations, and tenant isolation boundaries.

---

## 2. Logic Chain

1. **Absence of Prohibited Patterns**:
   - Hardcoded outputs: Recursive grep searches across `backend/app` and `agent/arka_agent` for `mock`, `fake`, `dummy`, `NotImplementedError`, and `TODO` returned zero matches.
   - Facade implementations: All functions in `RootcheckScanner` execute real operating system calls (`os.stat`, `os.listdir`, `psutil.pids`, `winreg.OpenKey`).
   - Self-certifying tests: Tests verify dynamic behavior against temporary file system layouts and known state inputs rather than validating static values hardcoded in both source and test.
2. **Structural & Behavioral Authenticity**:
   - The 12 SQLAlchemy models provide exact table and column structures matching the R2-R5 cybersecurity capabilities outlined in `PROJECT.md` and `ORIGINAL_REQUEST.md`.
   - The Pydantic schemas correctly map to database models and endpoint request/response payloads.
   - `RootcheckScanner` satisfies all requirements for R1: Known rootkit artifact scanner, Hidden process harvester, Backdoor & promiscuous socket scanner, and System binary & preload tampering detector.

---

## 3. Caveats

- Operating system-specific checks (such as Linux `/proc` and Windows `winreg`) gracefully branch according to `sys.platform` / `platform.system()`. When executing on a non-native platform (e.g. testing Linux `/proc` parsing while running on Windows), the scanner supports dependency injection (`proc_dir`, `sys_net_dir`, `preload_path`) which allows complete unit test validation in any environment.
- Live active kernel-level rootkits modifying kernel syscall tables in-memory cannot be fully simulated in user-space testing without root/ring-0 access; however, the detection surface correctly targets all user-space visible artifacts and discrepancies.

---

## 4. Conclusion

The implementation of Milestones M1 and M2 is authentic, comprehensive, and fully compliant with project standards.
- **Verdict**: **CLEAN**
- **Violations**: 0
- **Status**: PASSED

---

## 5. Verification Method

To independently verify the audited code:
1. Inspect models: `view_file backend/app/models/models.py` (lines 217-418).
2. Inspect schemas: `view_file backend/app/schemas/schemas.py` (lines 221-520).
3. Inspect rootcheck collector: `view_file agent/arka_agent/collectors/rootcheck.py`.
4. Run project test suite:
   ```bash
   pytest backend/tests/test_persistence.py agent/tests/test_rootcheck_and_syscollector.py -v
   ```
5. Run linting & type checks:
   ```bash
   ruff check backend/app/models backend/app/schemas agent/arka_agent/collectors/rootcheck.py
   mypy backend/app/models backend/app/schemas agent/arka_agent/collectors/rootcheck.py
   bandit -r backend/app agent/arka_agent -ll
   ```
