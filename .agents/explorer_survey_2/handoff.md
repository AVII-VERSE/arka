# Backend Services & API Survey Report (R2, R3, R4, R5)
**ARKA Enterprise SIEM & XDR Platform**

---

## 1. Observation

A detailed investigation was conducted across `backend/app/`, `backend/alembic/`, `backend/tests/`, and related agent modules (`agent/arka_agent/`). The findings regarding current architecture, database models, schemas, FastAPI endpoints, and services for R2, R3, R4, and R5 are documented below.

### 1.1 Core Architecture & Database Setup
- **FastAPI Entrypoint** (`backend/app/main.py:20-35`):
  - Uses `lifespan` context manager where `await conn.run_sync(Base.metadata.create_all)` runs on startup.
  - Exception handler handles `ARKAException` (`backend/app/main.py:59-71`).
  - CORS middleware configured for frontend ports 3000 and 5173 (`backend/app/main.py:50-56`).
  - Routes mounted via `app.include_router(api_router, prefix="/api/v1")` (`backend/app/main.py:74`).
- **Database Engine** (`backend/app/core/database.py:17-56`):
  - Uses SQLAlchemy 2.x async engine (`create_async_engine`) with `asyncpg` for PostgreSQL in production and `aiosqlite` for tests.
  - Base class: `class Base(DeclarativeBase)`.
  - Dependency: `get_db()` providing `AsyncSession` with auto-commit and rollback on exception.
- **Alembic Configuration** (`backend/alembic/env.py:10-18`):
  - Imports all models via `from app.models.models import *`.
  - Sets `target_metadata = Base.metadata`.
- **Existing Database Models** (`backend/app/models/models.py`):
  - Currently contains only 7 core models:
    1. `Tenant` (`models.py:71-82`)
    2. `User` (`models.py:84-97`)
    3. `Agent` (`models.py:99-114`)
    4. `DetectionRule` (`models.py:116-132`)
    5. `Alert` (`models.py:134-152`)
    6. `Incident` (`models.py:154-169`)
    7. `AuditLog` (`models.py:171-183`)
  - **Critical Gap**: Models for R2 (SCA), R3 (Syscollector Inventory), R4 (Active Response), and R5 (Vulnerability/CVE) are completely absent from PostgreSQL schema.

---

### 1.2 Module-by-Module Current State & Gaps

#### A. R2: Security Configuration Assessment (SCA) Engine
- **Endpoint** (`backend/app/api/v1/endpoints/sca.py:28-41`):
  - `POST /api/v1/sca/report` accepts `SCAPayload` and calls `SCAEngine.register_report(...)`.
  - `GET /api/v1/sca` calls `SCAEngine.get_tenant_reports(current_user.tenant_id)`.
- **Service** (`backend/app/services/sca_engine.py:7-58`):
  - Stores reports in an in-memory dictionary `_SCA_REPORT_STORE: dict[str, dict[str, Any]] = {}`.
  - Line 24-57 returns hardcoded mock report (`cis_benchmark_v2.0` with 3 dummy checks) when store is empty.
  - **Gaps**:
    1. No database persistence (PostgreSQL tables for policies, policy rules, scan reports, check results).
    2. No policy management (CIS Linux / CIS Windows benchmarks, uploading custom YAML/JSON policies).
    3. No historical compliance scoring or time-series tracking.
    4. No check-level query endpoints or tenant-wide compliance posture summaries.
    5. Mock fallback data violates zero-fake-data requirements.

#### B. R3: Syscollector System Inventory REST APIs & Models
- **Endpoint** (`backend/app/api/v1/endpoints/inventory.py:18-80`):
  - Uses in-memory dictionary `_INVENTORY_STORE: dict[str, dict[str, Any]] = {}`.
  - `POST /api/v1/inventory/snapshot` accepts `InventorySnapshotPayload` and writes to memory.
  - `GET /api/v1/inventory` on empty store falls back to `psutil` calls on the backend server itself (`inventory.py:50-76`), returning host machine data disguised as agent data.
- **Agent Collector** (`agent/arka_agent/collectors/syscollector.py:13-120`):
  - Collects hardware (cpu, ram, disks), OS metadata, network interfaces, and running processes.
  - Does not currently collect installed software packages or listening open ports in `syscollector.py` (though `vulnerability.py` extracts packages and `rootcheck.py` scans listening ports).
- **Gaps**:
  - No database models or tables for hardware, OS, network adapters, open ports, installed packages, and running processes.
  - No OpenSearch indexing for inventory snapshots (`arka-inventory-*`).
  - Missing sub-resource query endpoints (`GET /inventory/{agent_id}/hardware`, `/os`, `/packages`, `/network`, `/ports`, `/processes`).
  - Fake fallback data violates zero-fake-data requirements.

#### C. R4: Automated Active Response Service
- **Endpoint** (`backend/app/api/v1/endpoints/active_response.py:23-48`):
  - `POST /api/v1/active_response/trigger` creates a mock alert dict and invokes `ActiveResponseService.dispatch_alert_response(...)`.
  - `GET /api/v1/active_response` calls `ActiveResponseService.get_tenant_logs(...)`.
- **Service** (`backend/app/services/active_response_service.py:8-58`):
  - Uses an in-memory list `_ACTIVE_RESPONSE_LOGS: list[dict[str, Any]] = []`.
  - Static method automatically creates a log entry with `status: "EXECUTED"` and synthetic message, without any actual execution, validation, or agent dispatch.
  - Lines 45-57 return a hardcoded fake log (`ar-init-01`, `192.168.1.105`) when list is empty.
- **Agent Executor** (`agent/arka_agent/active_response.py:14-107`):
  - Implements `block_ip`, `kill_process`, `execute_command`, and quarantine directory creation.
- **Gaps**:
  - No database models (`ActiveResponseTask`, `ActiveResponsePolicy`).
  - No task lifecycle state machine (`PENDING` -> `DISPATCHED` -> `EXECUTING` -> `SUCCESS` / `FAILED` / `TIMEOUT`).
  - No agent dispatch / polling mechanism (agent cannot receive pending active response tasks via heartbeat or REST callback).
  - No safety validation or whitelisting (preventing self-DOS, blocking gateway/loopback, killing critical processes).
  - No real integration with `audit_logs` table.

#### D. R5: Vulnerability Detection & CVE Correlation Engine
- **Endpoint** (`backend/app/api/v1/endpoints/vulnerabilities.py:23-38`):
  - `POST /api/v1/vulnerabilities/scan` accepts `VulnerabilityScanPayload` with a list of packages and calls `VulnerabilityEngine.correlate_packages(...)`.
  - `GET /api/v1/vulnerabilities` calls `VulnerabilityEngine.get_tenant_vulnerabilities(...)`.
- **Service** (`backend/app/services/vulnerability_engine.py:9-103`):
  - Contains a static list of 4 hardcoded CVE dictionaries (`CVE-2021-44228`, `CVE-2022-0778`, `CVE-2023-38545`, `CVE-2021-3156`).
  - Performs primitive exact string matching: `pkg_ver in cve["vulnerable_versions"]` (`vulnerability_engine.py:64`).
  - Stores reports in in-memory dictionary `_VULNERABILITY_REPORTS`.
  - Lines 96-102 return synthetic mock report for `agent-dev-01` when empty.
- **Gaps**:
  - No database models (`CVEItem` / `VulnerabilityDefinition`, `VulnerabilityFinding`, `VulnerabilityScanReport`).
  - No semantic version range comparison (e.g. `< 2.17.1`, `>= 2.0, < 2.15.0`, packaging version comparison).
  - No CVSS v3 score / vector calculator or CWE classification.
  - No finding lifecycle tracking (`ACTIVE` -> `MITIGATED` -> `RESOLVED` -> `FALSE_POSITIVE` -> `SUPPRESSED`).
  - No automated trigger when Syscollector ingests new software inventory.

---

## 2. Logic Chain

From the observations above, the following logical steps define the required backend architecture:

```
[Agent Telemetry Ingestion]
        │
        ├──> SCA Collector (CIS Scans)
        │       └──> POST /api/v1/sca/report ───────────────> SCAEngine ───> PostgreSQL (SCAPolicy, SCAScanReport, SCACheckResult)
        │
        ├──> Syscollector (Hardware, OS, Network, Ports, Packages, Processes)
        │       └──> POST /api/v1/inventory/snapshot ───────> InventoryService ───┬───> PostgreSQL (AgentInventory* canonical tables)
        │                                                                          ├───> OpenSearch (arka-inventory-* time-series)
        │                                                                          └───> Auto-trigger VulnerabilityEngine
        │
        ├──> Vulnerability Correlation
        │       └──> VulnerabilityEngine ────────────────────────────────────────> PostgreSQL (CVEItem, VulnerabilityFinding, ScanReport)
        │               │ (CVSS v3, Semantic Version Ranges)
        │               └───> [High/Critical Finding] ───────> Emit Alert ───┐
        │                                                                    │
        └──> Active Response Pipeline <──────────────────────────────────────┘
                ├──> Automated Trigger (High/Critical Alerts)
                ├──> Manual Trigger (POST /api/v1/active_response/trigger)
                └──> ActiveResponseService
                        ├──> Safety & Whitelist Validator
                        ├──> PostgreSQL (ActiveResponseTask, AuditLog)
                        └──> Agent Dispatch (Heartbeat queue / REST callback)
```

### 2.1 Database Schema Requirements (SQLAlchemy 2.x Models)

To support real persistence without fake data, the following models must be defined in `backend/app/models/models.py`:

```python
# --- R2: Security Configuration Assessment (SCA) Models ---

class SCAPolicy(Base):
    __tablename__ = "sca_policies"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    policy_code: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    os_type: Mapped[str] = mapped_column(String(50), nullable=False)  # "linux", "windows", "all"
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    rules_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

class SCAScanReport(Base):
    __tablename__ = "sca_scan_reports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("agents.id"), nullable=False, index=True)
    policy_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    policy_name: Mapped[str] = mapped_column(String(255), nullable=False)
    compliance_score: Mapped[float] = mapped_column(Float, nullable=False)
    total_checks: Mapped[int] = mapped_column(Integer, nullable=False)
    passed_checks: Mapped[int] = mapped_column(Integer, nullable=False)
    failed_checks: Mapped[int] = mapped_column(Integer, nullable=False)
    not_applicable_checks: Mapped[int] = mapped_column(Integer, nullable=False)
    checks: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

# --- R3: Syscollector System Inventory Models ---

class AgentInventoryHardware(Base):
    __tablename__ = "agent_inventory_hardware"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("agents.id"), nullable=False, unique=True, index=True)
    cpu_cores_logical: Mapped[int] = mapped_column(Integer, default=1)
    cpu_cores_physical: Mapped[int] = mapped_column(Integer, default=1)
    cpu_architecture: Mapped[str] = mapped_column(String(50), nullable=False)
    ram_total_gb: Mapped[float] = mapped_column(Float, nullable=False)
    disks: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

class AgentInventoryOS(Base):
    __tablename__ = "agent_inventory_os"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("agents.id"), nullable=False, unique=True, index=True)
    os_name: Mapped[str] = mapped_column(String(100), nullable=False)
    os_release: Mapped[str] = mapped_column(String(100), nullable=False)
    os_version: Mapped[str] = mapped_column(String(100), nullable=False)
    kernel_architecture: Mapped[str] = mapped_column(String(50), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    python_version: Mapped[str] = mapped_column(String(50), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

class AgentInventoryPackage(Base):
    __tablename__ = "agent_inventory_packages"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("agents.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(100), nullable=False)
    format: Mapped[str | None] = mapped_column(String(50), nullable=True)  # deb, rpm, win, pip
    architecture: Mapped[str | None] = mapped_column(String(50), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

class AgentInventoryNetwork(Base):
    __tablename__ = "agent_inventory_network"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("agents.id"), nullable=False, index=True)
    interface_name: Mapped[str] = mapped_column(String(100), nullable=False)
    ipv4_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    ipv6_address: Mapped[str | None] = mapped_column(String(100), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(50), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

class AgentInventoryPort(Base):
    __tablename__ = "agent_inventory_ports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("agents.id"), nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False)  # tcp, udp
    local_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    local_port: Mapped[int] = mapped_column(Integer, nullable=False)
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    state: Mapped[str | None] = mapped_column(String(50), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

class AgentInventoryProcess(Base):
    __tablename__ = "agent_inventory_processes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("agents.id"), nullable=False, index=True)
    pid: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cpu_percent: Mapped[float] = mapped_column(Float, default=0.0)
    memory_percent: Mapped[float] = mapped_column(Float, default=0.0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

# --- R4: Automated Active Response Models ---

class ActiveResponseTaskStatusEnum(str, enum.Enum):
    PENDING = "PENDING"
    DISPATCHED = "DISPATCHED"
    EXECUTING = "EXECUTING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"

class ActiveResponseActionEnum(str, enum.Enum):
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    KILL_PROCESS = "kill_process"
    LOCK_USER = "lock_user"
    ISOLATE_HOST = "isolate_host"
    RECONNECT_HOST = "reconnect_host"
    QUARANTINE_FILE = "quarantine_file"

class ActiveResponseTask(Base):
    __tablename__ = "active_response_tasks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("agents.id"), nullable=False, index=True)
    action: Mapped[ActiveResponseActionEnum] = mapped_column(SQLEnum(ActiveResponseActionEnum), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[ActiveResponseTaskStatusEnum] = mapped_column(
        SQLEnum(ActiveResponseTaskStatusEnum), default=ActiveResponseTaskStatusEnum.PENDING, index=True
    )
    trigger_alert_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("alerts.id"), nullable=True)
    triggered_by_user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    command_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stdout: Mapped[str | None] = mapped_column(Text, nullable=True)
    stderr: Mapped[str | None] = mapped_column(Text, nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

# --- R5: Vulnerability Detection & CVE Correlation Models ---

class VulnerabilityStatusEnum(str, enum.Enum):
    ACTIVE = "ACTIVE"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SUPPRESSED = "SUPPRESSED"

class CVEItem(Base):
    __tablename__ = "cve_items"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    cve_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    package_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    affected_versions_spec: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g. "<2.17.1", "==1.1.1t"
    fixed_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    severity: Mapped[SeverityEnum] = mapped_column(SQLEnum(SeverityEnum), nullable=False, index=True)
    cvss_score: Mapped[float] = mapped_column(Float, nullable=False)
    cvss_vector: Mapped[str | None] = mapped_column(String(100), nullable=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

class VulnerabilityFinding(Base):
    __tablename__ = "vulnerability_findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("agents.id"), nullable=False, index=True)
    cve_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    package_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    installed_version: Mapped[str] = mapped_column(String(100), nullable=False)
    fixed_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    severity: Mapped[SeverityEnum] = mapped_column(SQLEnum(SeverityEnum), nullable=False, index=True)
    cvss_score: Mapped[float] = mapped_column(Float, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[VulnerabilityStatusEnum] = mapped_column(
        SQLEnum(VulnerabilityStatusEnum), default=VulnerabilityStatusEnum.ACTIVE, index=True
    )
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

class VulnerabilityScanReport(Base):
    __tablename__ = "vulnerability_scan_reports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("agents.id"), nullable=False, index=True)
    scanned_packages_count: Mapped[int] = mapped_column(Integer, nullable=False)
    vulnerability_count: Mapped[int] = mapped_column(Integer, nullable=False)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
```

---

## 3. Caveats

1. **Database Schema Auto-Creation vs. Alembic Migrations**:
   - The test suite uses SQLite in-memory with `Base.metadata.create_all`, which automatically creates all declared models without running Alembic migration scripts.
   - For local development / production, `lifespan` in `backend/app/main.py` also calls `Base.metadata.create_all` safely inside a try/except block.
   - However, an Alembic migration script should be generated once the models are consolidated so production PostgreSQL upgrades are tracked cleanly.
2. **OpenSearch Availability in Test Environments**:
   - `OpenSearchEventService` currently includes an in-memory fallback list (`_indexed_events`), allowing unit and integration tests to execute seamlessly without an external OpenSearch cluster running.
   - When extending `OpenSearchEventService` for syscollector inventory snapshots (`arka-inventory-*`), the same dual pattern (OpenSearch client + fallback buffer) should be maintained for 100% test compatibility.
3. **Agent Active Response Communication**:
   - Agents operate behind firewalls and connect outbound to backend.
   - Response dispatching must support two modes:
     a. **Polling / Heartbeat Pull**: Agent periodically calls `GET /api/v1/active_response/agents/{agent_id}/pending` or receives tasks in the heartbeat response `POST /api/v1/agents/heartbeat`.
     b. **Direct Push / Ingestion Return**: For immediate containment actions, return pending tasks in ingestion response headers or dedicated WebSocket/Kafka channel.

---

## 4. Conclusion & Concrete Recommendations

### 4.1 Recommended Implementation Plan

| Step | Target Files | Key Actions |
|---|---|---|
| **1. Database Models** | `backend/app/models/models.py` | Add all 12 missing SQLAlchemy models for R2, R3, R4, R5 with proper foreign keys, enums, indexes, and UTC timestamps. |
| **2. Pydantic Schemas** | `backend/app/schemas/schemas.py` | Add comprehensive schemas for R2 (SCA report, checks, summary, policy), R3 (inventory sub-models: hardware, OS, network, ports, packages, processes, snapshots), R4 (active response tasks, triggers, status callbacks), R5 (CVE items, findings, reports, status updates). |
| **3. SCA Engine Service** | `backend/app/services/sca_engine.py` | Refactor `SCAEngine` to accept `AsyncSession`, compute real compliance scores `(passed / (passed + failed) * 100.0)`, persist `SCAScanReport`, provide summary aggregations, eliminate all fake fallback dictionaries. |
| **4. Inventory Service & Router** | `backend/app/services/inventory_service.py`<br>`backend/app/api/v1/endpoints/inventory.py` | Implement `InventoryService` for atomic UPSERT into relational tables + OpenSearch indexing; implement sub-resource endpoints (`/hardware`, `/os`, `/packages`, `/network`, `/ports`, `/processes`); remove server psutil mock fallback. |
| **5. Active Response Service** | `backend/app/services/active_response_service.py`<br>`backend/app/api/v1/endpoints/active_response.py` | Implement `ActiveResponseService` with target validation (IP/PID whitelist), safety checks, DB task lifecycle management (`PENDING` -> `SUCCESS`/`FAILED`), automated alert trigger, agent callback endpoint, audit trail generation. |
| **6. Vulnerability Correlation Engine** | `backend/app/services/vulnerability_engine.py`<br>`backend/app/api/v1/endpoints/vulnerabilities.py` | Implement `VulnerabilityEngine` with semantic version range parsing (`packaging.version`), seeded CVE database, persistent `VulnerabilityFinding` records, CVSS calculation, finding status mutations, alert emission on Critical CVEs. |
| **7. Cross-Engine Automation** | `backend/app/api/v1/endpoints/events.py`<br>`backend/app/api/v1/endpoints/inventory.py` | Wire automated vulnerability scanning on package inventory ingestion; wire automated active response triggering on `BRUTE_FORCE_LOGIN` or CRITICAL alerts. |

---

## 5. Verification Method

To verify the backend implementation independently:

1. **Unit & Persistence Tests**:
   - Create `backend/tests/test_sca_engine.py`: Test policy persistence, report ingestion, compliance score calculation, and empty-state handling.
   - Create `backend/tests/test_inventory_service.py`: Test snapshot ingestion, relational table UPSERTs, component retrieval endpoints (`/hardware`, `/os`, `/packages`, `/ports`, `/processes`).
   - Create `backend/tests/test_active_response_service.py`: Test automated alert response triggering, manual trigger, IP/PID safety whitelist guards, task status updates, and audit trail generation.
   - Create `backend/tests/test_vulnerability_engine.py`: Test semantic version range matching (e.g. `< 2.17.1`), CVE correlation with package inventory, finding lifecycle mutations, and zero-fake data compliance.
2. **Full Test Suite Execution Command**:
   ```powershell
   python -m pytest backend/tests agent/tests -v
   ```
3. **Static Analysis & Linters**:
   ```powershell
   ruff check backend agent
   mypy backend/app
   bandit -r backend/app -ll
   ```
4. **Zero Fake Data Invalidation Condition**:
   - If querying `/api/v1/inventory`, `/api/v1/sca`, `/api/v1/active_response`, or `/api/v1/vulnerabilities` against an empty database returns anything other than an empty list `[]` or 404, the implementation fails verification.
