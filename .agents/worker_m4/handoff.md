# Handoff Report — Milestone M4 (R3: Syscollector System Inventory Harvester & REST APIs)

**Worker Agent**: `worker_m4`
**Milestone**: M4 (R3: Syscollector System Inventory Harvester & REST APIs)
**Date**: 2026-08-27

---

## 1. Observation

### 1.1 Initial State Observations
- **Agent Harvester (`agent/arka_agent/collectors/syscollector.py:13-121`)**:
  - `SyscollectorHarvester` was an isolated class not subclassing `BaseCollector`.
  - It collected only basic hardware, OS info, network interfaces, and running processes.
  - Software package harvesting was completely missing (`get_installed_packages` did not exist).
  - Open port and socket connection enumeration was missing.
  - Process metadata lacked `ppid`, `exe`, `cmdline`, `status`, `create_time`, and `num_threads`.
- **Backend Endpoints (`backend/app/api/v1/endpoints/inventory.py:18-80`)**:
  - Used an in-memory dictionary `_INVENTORY_STORE: dict[str, dict[str, Any]] = {}`.
  - Stored incoming snapshots only in memory without relational database persistence.
  - Lines 49-77 fell back to `psutil` calls on the backend server itself when the store was empty, returning host machine data disguised as agent telemetry (a fake mock fallback violation).
  - Sub-resource endpoints (`/hardware`, `/os`, `/packages`, `/network`, `/ports`, `/processes`) were absent.
- **Backend Service (`backend/app/services/inventory_service.py`)**:
  - Did not exist.

### 1.2 Implemented Changes
- **`agent/arka_agent/collectors/syscollector.py`**:
  - Subclassed `BaseCollector(name="syscollector", enabled=enabled)`.
  - Implemented `get_installed_packages()` with pure parsers for Debian/Ubuntu (`dpkg-query` and `/var/lib/dpkg/status`), RedHat/CentOS (`rpm -qa`), Alpine (`apk info -v`), Windows Registry (`winreg`), and Python distributions (`importlib.metadata.distributions()`).
  - Implemented `get_network_ports(custom_connections=None)` with `protocol`, `local_ip`, `local_port`, `remote_ip`, `remote_port`, `state`, `pid`, `process_name`, `exe_path`.
  - Implemented `get_network_interfaces()` with IPv4, IPv6, MAC, Netmask, Broadcast, Status, Speed, MTU.
  - Implemented `get_hardware_info()` and `get_os_info()` with CPU cores, RAM, Swap, Disks, Boot Time, and Uptime.
  - Implemented `get_running_processes(limit=...)` capturing full process tree lineage metadata.
  - Implemented `collect_inventory()` generating full `InventorySnapshotPayload` dictionary and `collect()` adhering to `BaseCollector`.
- **`backend/app/services/inventory_service.py`**:
  - Implemented `InventoryService` with async SQLAlchemy 2.x persistence via `AsyncSession`.
  - Implemented atomic UPSERT for `AgentInventoryHardware` and `AgentInventoryOS`.
  - Implemented atomic DELETE + INSERT replacement for `AgentInventoryPackage`, `AgentInventoryNetwork`, `AgentInventoryPort`, `AgentInventoryProcess` per agent snapshot.
  - Implemented sub-resource query methods: `get_inventory_summary`, `get_hardware`, `get_os`, `get_packages`, `get_network`, `get_ports`, `get_processes`.
- **`backend/app/api/v1/endpoints/inventory.py`**:
  - Implemented `POST /api/v1/inventory/snapshot` (status code 201).
  - Implemented `GET /api/v1/inventory` returning `list[AgentInventorySummary]` per tenant.
  - Implemented `GET /api/v1/inventory/{agent_id}/hardware` -> `HardwareInventoryRead`.
  - Implemented `GET /api/v1/inventory/{agent_id}/os` -> `OSInventoryRead`.
  - Implemented `GET /api/v1/inventory/{agent_id}/packages` -> `list[PackageInventoryRead]`.
  - Implemented `GET /api/v1/inventory/{agent_id}/network` -> `list[NetworkInventoryRead]`.
  - Implemented `GET /api/v1/inventory/{agent_id}/ports` -> `list[PortInventoryRead]`.
  - Implemented `GET /api/v1/inventory/{agent_id}/processes` -> `list[ProcessInventoryRead]`.
  - Completely eliminated all server `psutil` mocks (empty states return 404 or `[]`).
- **`agent/tests/test_syscollector.py`**:
  - 20 unit and integration tests covering hardware, OS metadata, all 5 package managers/parsers, network interfaces, open ports, running processes, snapshot payload generation, and resilience.
- **`backend/tests/test_inventory_service.py`**:
  - 7 integration and REST API tests covering ingestion, relational persistence, atomic upsert/replace, summary, sub-resources, tenant isolation, and zero-fake-data empty states.

### 1.3 Verbatim Verification Outputs
- **pytest output**:
  ```
  backend\tests\test_inventory_service.py .......                          [ 25%]
  backend ....................                                             [100%]
  ============================= 27 passed in 11.21s =============================
  ```
- **Existing tests (`agent/tests/test_rootcheck_and_syscollector.py`)**:
  ```
  ======================== 27 passed, 1 skipped in 6.40s ========================
  ```
- **ruff check**:
  ```
  & d:\ARKA\backend\.venv\Scripts\ruff.exe check backend agent
  All checks passed!
  ```
- **mypy**:
  ```
  & d:\ARKA\backend\.venv\Scripts\mypy.exe backend/app/services/inventory_service.py backend/app/api/v1/endpoints/inventory.py agent/arka_agent/collectors/syscollector.py
  Success: no issues found in 3 source files
  ```
- **bandit**:
  ```
  & d:\ARKA\backend\.venv\Scripts\bandit.exe -r backend/app agent/arka_agent -ll
  No issues identified.
  Total issues (by severity): Undefined: 0, Low: 12, Medium: 0, High: 0
  ```

---

## 2. Logic Chain

1. **Endpoint Collector Reliability**: Downstream vulnerability correlation (R5 CVE engine) and posture management require genuine inventory data. By implementing native package parsers (`dpkg`, `rpm`, `apk`, `winreg`, `importlib`) and network/process extractors with fallbacks, `SyscollectorHarvester` collects complete host telemetry without synthetic shortcuts.
2. **Snapshot Consistency via Atomic UPSERT & Replace**: Hardware and OS metadata are single-instance entities per host, so in-place update (UPSERT) preserves record IDs while updating metrics. Software packages, network interfaces, open ports, and running processes represent point-in-time collections that can shrink or grow; performing an atomic delete-and-insert transaction per agent snapshot guarantees stale removed packages or closed ports do not linger in the database.
3. **Zero Fake Data & Tenant Isolation**: Removing backend `psutil` mock fallbacks in `inventory.py` and enforcing `tenant_id` filtering in all queries ensures true multi-tenant boundary enforcement. Non-existent agents return 404 for single resources and empty lists `[]` for collections, fulfilling strict integrity standards.

---

## 3. Caveats

- **Operating System Packages Availability**: When executing on an OS without a package manager (e.g. Debian binaries on Windows), `_harvest_debian_packages` safely returns an empty list, and the harvester continues with Windows Registry and Python `importlib` distributions. Unit tests verify the parsing functions independently with verbatim package manager outputs.
- **Port Enumeration Permissions**: On non-root Linux or non-admin Windows, resolving certain socket owning PIDs or process names may encounter `AccessDenied`. The harvester catches these exceptions gracefully and records available port and IP data with `pid=None`.

---

## 4. Conclusion

Milestone M4 (R3: Syscollector System Inventory Harvester & REST APIs) is completely implemented and verified. All required files:
- `agent/arka_agent/collectors/syscollector.py`
- `backend/app/services/inventory_service.py`
- `backend/app/api/v1/endpoints/inventory.py`
- `agent/tests/test_syscollector.py`
- `backend/tests/test_inventory_service.py`

are fully functional, have 100% test pass rates across 27 new tests and 27 existing tests, pass all static quality gates (ruff, mypy, bandit), and contain zero mock or synthetic fallback data.

---

## 5. Verification Method

To independently verify this milestone:

1. **Run target pytest suite**:
   ```powershell
   & d:\ARKA\backend\.venv\Scripts\pytest.exe backend/tests/test_inventory_service.py agent/tests/test_syscollector.py -v
   ```
   *Expected outcome*: 27 passed.

2. **Run existing rootcheck and syscollector tests**:
   ```powershell
   & d:\ARKA\backend\.venv\Scripts\pytest.exe agent/tests/test_rootcheck_and_syscollector.py -v
   ```
   *Expected outcome*: 27 passed, 1 skipped.

3. **Run linter**:
   ```powershell
   & d:\ARKA\backend\.venv\Scripts\ruff.exe check backend agent
   ```
   *Expected outcome*: `All checks passed!`.

4. **Run type checker**:
   ```powershell
   & d:\ARKA\backend\.venv\Scripts\mypy.exe backend/app/services/inventory_service.py backend/app/api/v1/endpoints/inventory.py agent/arka_agent/collectors/syscollector.py
   ```
   *Expected outcome*: `Success: no issues found in 3 source files`.

5. **Run security scanner**:
   ```powershell
   & d:\ARKA\backend\.venv\Scripts\bandit.exe -r backend/app agent/arka_agent -ll
   ```
   *Expected outcome*: `No issues identified.` (0 Medium/High issues).
