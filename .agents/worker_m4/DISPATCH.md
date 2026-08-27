## 2026-08-27T04:10:26Z
You are teamwork_preview_worker #4 for Milestone M4 (R3: Syscollector System Inventory Harvester & REST APIs).

Your Working Directory: d:/ARKA/.agents/worker_m4
Original Request Path: d:/ARKA/.agents/ORIGINAL_REQUEST.md
Project Scope Document: d:/ARKA/PROJECT.md
Survey Reference: d:/ARKA/.agents/explorer_survey_1/handoff.md § 4.4 and d:/ARKA/.agents/explorer_survey_2/handoff.md § 2.1

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Scope & Exclusively Owned Files:
- `agent/arka_agent/collectors/syscollector.py`
- `backend/app/services/inventory_service.py`
- `backend/app/api/v1/endpoints/inventory.py`
- `agent/tests/test_syscollector.py`
- `backend/tests/test_inventory_service.py`

Tasks:
1. Initialize `progress.md` and `BRIEFING.md` in `d:/ARKA/.agents/worker_m4`.
2. Implement `SyscollectorHarvester` in `agent/arka_agent/collectors/syscollector.py`:
   - Subclasses `BaseCollector(name="syscollector", enabled=enabled)`.
   - Comprehensive package harvester (`get_installed_packages`) extracting real software inventory across Linux Debian/Ubuntu (`dpkg-query`), RedHat/CentOS (`rpm -qa`), Alpine (`apk info`), Windows Registry (`winreg` Uninstall keys), and Python environment (`importlib.metadata.distributions()`).
   - Network connections & listening ports (`get_network_ports`): Protocol, Local IP/Port, Remote IP/Port, PID, Process Name, Executable Path.
   - Network interfaces (`get_network_interfaces`): Name, IPv4, IPv6, MAC, Netmask, Status, Speed, MTU.
   - Hardware & OS metadata (`get_hardware_info`, `get_os_info`): CPU cores, RAM total/available/used, Disks, OS name, release, version, kernel arch, hostname, python version, uptime.
   - Running processes (`get_running_processes`): PID, PPID, name, exe, cmdline, username, cpu_percent, memory_percent.
   - Generates full `InventorySnapshotPayload` dictionary with zero fake data.
3. Implement `InventoryService` in `backend/app/services/inventory_service.py` and endpoints in `backend/app/api/v1/endpoints/inventory.py`:
   - Accept `AsyncSession` database dependency.
   - Atomic UPSERT into canonical relational tables: `AgentInventoryHardware`, `AgentInventoryOS`, `AgentInventoryPackage`, `AgentInventoryNetwork`, `AgentInventoryPort`, `AgentInventoryProcess`.
   - Sub-resource endpoints:
     - `POST /api/v1/inventory/snapshot`
     - `GET /api/v1/inventory` (all agents summary per tenant)
     - `GET /api/v1/inventory/{agent_id}/hardware`
     - `GET /api/v1/inventory/{agent_id}/os`
     - `GET /api/v1/inventory/{agent_id}/packages`
     - `GET /api/v1/inventory/{agent_id}/network`
     - `GET /api/v1/inventory/{agent_id}/ports`
     - `GET /api/v1/inventory/{agent_id}/processes`
   - ELIMINATE all server psutil fallback mocks! (Empty DB returns 404 or empty list).
4. Implement tests:
   - `agent/tests/test_syscollector.py`: Hardware, OS, package parsing (dpkg, rpm, apk, winreg, importlib), network interfaces, ports, processes, snapshot payload generation, error resilience.
   - `backend/tests/test_inventory_service.py`: Snapshot ingestion, relational persistence, sub-resource retrieval, tenant isolation, zero-fake-data empty state verification.
5. Verification:
   - `python -m pytest backend/tests/test_inventory_service.py agent/tests/test_syscollector.py -v`
   - `ruff check backend agent`
   - `mypy backend/app agent/arka_agent`
   - `bandit -r backend/app agent/arka_agent -ll`
6. Write `handoff.md` and send a completion message.
