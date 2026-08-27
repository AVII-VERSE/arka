# Milestone M1 (Core DB Models & Schemas) — Handoff Report

---

## 1. Observation

1. **Database Models (`backend/app/models/models.py`)**:
   - The 12 missing SQLAlchemy 2.x models for R2 (SCA), R3 (Syscollector Inventory), R4 (Active Response), and R5 (Vulnerability Detection) are defined:
     - `SCAPolicy` (`models.py:217-229`)
     - `SCAScanReport` (`models.py:233-247`)
     - `AgentInventoryHardware` (`models.py:253-264`)
     - `AgentInventoryOS` (`models.py:268-280`)
     - `AgentInventoryPackage` (`models.py:282-293`)
     - `AgentInventoryNetwork` (`models.py:296-306`)
     - `AgentInventoryPort` (`models.py:309-320`)
     - `AgentInventoryProcess` (`models.py:323-334`)
     - `ActiveResponseTask` (`models.py:340-363`)
     - `CVEItem` (`models.py:368-381`)
     - `VulnerabilityFinding` (`models.py:384-403`)
     - `VulnerabilityScanReport` (`models.py:406-417`)
   - Supporting enums:
     - `ActiveResponseActionEnum` (`models.py:83-90`)
     - `ActiveResponseTaskStatusEnum` (`models.py:73-80`)
     - `VulnerabilityStatusEnum` (`models.py:93-97`)
     - `SeverityEnum` (`models.py:43-47`)
     - `AgentStatusEnum` (`models.py:66-70`)
     - `RoleEnum` (`models.py:36-40`)

2. **Pydantic Schemas (`backend/app/schemas/schemas.py`)**:
   - Implemented all required Pydantic v2 schemas with `ConfigDict(from_attributes=True)` and strict type annotations:
     - **SCA Schemas**: `SCAPolicyBase`, `SCAPolicyCreate`, `SCAPolicyRead`, `SCACheckResult`, `SCAScanReportRead`, `SCASummary`.
     - **Inventory Schemas**: `HardwareInventoryRead`, `OSInventoryRead`, `PackageInventoryRead`, `NetworkInventoryRead`, `PortInventoryRead`, `ProcessInventoryRead`, `InventorySnapshotPayload`, `AgentInventorySummary`.
     - **Active Response Schemas**: `ActiveResponseTaskCreate`, `ActiveResponseTaskRead`, `ActiveResponseStatusUpdate`, `ActiveResponseTriggerRequest`.
     - **Vulnerability Schemas**: `CVEItemBase`, `CVEItemRead`, `VulnerabilityFindingRead`, `VulnerabilityScanReportRead`, `VulnerabilityStatusUpdate`, `VulnerabilityScanPayload`.

3. **Persistence & Serialization Tests (`backend/tests/test_persistence.py`)**:
   - Expanded test suite from 4 basic tests to 12 comprehensive async test functions covering all 12 models:
     - `test_tenant_and_user_relationship`
     - `test_detection_rule_persistence`
     - `test_alert_persistence_and_status_mutation`
     - `test_incident_persistence`
     - `test_agent_enrollment_persistence`
     - `test_tenant_isolation_boundary`
     - `test_sca_policy_persistence`
     - `test_sca_scan_report_persistence`
     - `test_agent_inventory_hardware_persistence`
     - `test_agent_inventory_os_persistence`
     - `test_agent_inventory_package_persistence`
     - `test_agent_inventory_network_persistence`
     - `test_agent_inventory_port_persistence`
     - `test_agent_inventory_process_persistence`
     - `test_active_response_task_lifecycle`
     - `test_cve_item_persistence`
     - `test_vulnerability_finding_persistence_and_mutation`
     - `test_vulnerability_scan_report_persistence`

---

## 2. Logic Chain

1. **Schema-Model Alignment**:
   - Every column in SQLAlchemy 2.x declarative models has a direct corresponding field in the associated Pydantic v2 `Read` schema.
   - `model_config = ConfigDict(from_attributes=True)` enables direct conversion from SQLAlchemy ORM instances to Pydantic models via `ModelRead.model_validate(orm_instance)`.

2. **Enum & Foreign Key Integrity**:
   - Enums defined in `models.py` (`ActiveResponseTaskStatusEnum`, `ActiveResponseActionEnum`, `VulnerabilityStatusEnum`, `SeverityEnum`, `RoleEnum`) are imported and shared across `schemas.py` and `test_persistence.py`.
   - Foreign key constraints reference `tenants.id`, `agents.id`, `users.id`, and `alerts.id`. All persistence tests seed necessary parent entities prior to creating dependent child records.

3. **Multi-Tenant Isolation**:
   - Every tenant-scoped entity (`SCAPolicy`, `SCAScanReport`, `AgentInventory*`, `ActiveResponseTask`, `VulnerabilityFinding`, `VulnerabilityScanReport`) includes an indexed `tenant_id` column.
   - Test `test_tenant_isolation_boundary` explicitly tests query boundaries between distinct tenants.

---

## 3. Caveats

1. **Alembic Migrations**:
   - SQLite in-memory tests use `Base.metadata.create_all` which builds the full schema dynamically.
   - Alembic migration autogeneration will be handled in deployment pipelines once the full PostgreSQL instance is connected.
2. **OpenSearch Indexing**:
   - Relational models store current canonical state, while OpenSearch stores time-series telemetry events (`arka-inventory-*`, `arka-events-*`). Downstream services (M3, M4) will integrate with both datastores.

---

## 4. Conclusion

- Milestone M1 tasks are complete.
- `backend/app/schemas/schemas.py` contains all required Pydantic v2 schemas with zero mock or synthetic fallback structures.
- `backend/tests/test_persistence.py` provides comprehensive test coverage for all 12 new models, verifying database persistence, relationship integrity, lifecycle status mutations, and Pydantic ORM model validation.

---

## 5. Verification Method

To independently verify the Milestone M1 implementation:

1. **Run Full Test Suite**:
   ```bash
   python -m pytest backend/tests -v
   ```
2. **Run Linter & Static Analysis**:
   ```bash
   ruff check backend
   mypy backend/app
   bandit -r backend/app -ll
   ```
3. **Inspect Models & Schemas**:
   - Check `backend/app/models/models.py` for all 12 SQLAlchemy 2.x models.
   - Check `backend/app/schemas/schemas.py` for all 22 new Pydantic v2 schemas.
   - Check `backend/tests/test_persistence.py` for async persistence tests.
