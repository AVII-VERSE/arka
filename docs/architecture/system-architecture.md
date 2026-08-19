# System Architecture Blueprint — ARKA

## System Architecture Diagram

```
+-----------------------------------------------------------------------+
|                           ENDPOINT LAYER                              |
|   +--------------------------+          +-------------------------+   |
|   |  ARKA Agent (Windows)    |          |   ARKA Agent (Linux)    |   |
|   |  - EventLog Collector    |          |   - Syslog Collector    |   |
|   |  - SQLite Local Buffer   |          |   - SQLite Local Buffer |   |
|   +------------+-------------+          +------------+------------+   |
+----------------|-------------------------------------|----------------+
                 | HTTPS / mTLS                        | HTTPS / mTLS
                 v                                     v
+-----------------------------------------------------------------------+
|                         INGESTION & API LAYER                         |
|   +---------------------------------------------------------------+   |
|   |                 FastAPI Ingestion Gateway                     |   |
|   |  - Auth & mTLS Validation                                     |   |
|   |  - Tenant Rate Limiter (Redis)                                |   |
|   |  - Schema Validation (Pydantic v2)                            |   |
|   +-------------------------------+-------------------------------+   |
+-----------------------------------|-----------------------------------+
                                    | Produce Raw JSON
                                    v
+-----------------------------------------------------------------------+
|                         EVENT STREAMING BUS                           |
|   +---------------------------------------------------------------+   |
|   |                    Apache Kafka Cluster                       |   |
|   |  Topics:                                                      |   |
|   |  - arka.events.raw                                            |   |
|   |  - arka.events.normalized                                     |   |
|   |  - arka.alerts                                                |   |
|   |  - arka.events.dlq                                            |   |
|   +-------------------------------+-------------------------------+   |
+-----------------------------------|-----------------------------------+
                                    | Consume Raw Events
                                    v
+-----------------------------------------------------------------------+
|                      PROCESSING & STORAGE LAYER                       |
|   +-------------------------------+   +---------------------------+   |
|   |  Event Normalizer Engine      |   | PostgreSQL 16             |   |
|   |  - Timestamp Normalization    |   | - Tenant Configurations   |   |
|   |  - Taxonomy Mapping           |   | - Users & Roles (RBAC)    |   |
|   |  - Metadata Enrichment        |   | - Detection Rules         |   |
|   +---------------+---------------+   | - Alerts & Incidents      |   |
|                   |                   | - Audit Logs              |   |
|                   v                   +-------------+-------------+   |
|   +-------------------------------+                 |                 |   |
|   | OpenSearch 2.x                |                 |                 |   |
|   | - High-Throughput Storage     |                 |                 |   |
|   | - Full-Text Event Search      |                 |                 |   |
|   | - Index: arka-events-{tenant} |                 |                 |   |
|   +---------------+---------------+                 |                 |   |
+-------------------|---------------------------------|-----------------+
                    |                                 |
                    v                                 v
+-----------------------------------------------------------------------+
|                         DETECTION & ALERTING                          |
|   +---------------------------------------------------------------+   |
|   |             ARKA Detection & Correlation Engine               |   |
|   |  - Deterministic Rule Evaluator                               |   |
|   |  - Redis Sliding Time-Window State Store                      |   |
|   |  - MITRE ATT&CK Mapping                                       |   |
|   |  - Alert Producer & Incident Aggregator                       |   |
|   +-------------------------------+-------------------------------+   |
+-----------------------------------|-----------------------------------+
                                    | API REST / WebSockets
                                    v
+-----------------------------------------------------------------------+
|                        SOC DASHBOARD FRONTEND                         |
|   +---------------------------------------------------------------+   |
|   |         React 18 + TypeScript + Vite + Tailwind UI            |   |
|   |  - Real-Time Event Rate & Alert Summary                       |   |
|   |  - OpenSearch Event Explorer & Facet Search                   |   |
|   |  - Alert Drawer & Incident Triage Workflow                    |   |
|   +---------------------------------------------------------------+   |
+-----------------------------------------------------------------------+
```

---

## Component Responsibilities

### 1. Endpoint Layer (`agent/`)
Cross-platform daemon deployed on target hosts. Collects security telemetry (logon failures, privilege escalation, process spawns), writes to a local SQLite buffer during network outages, and pushes events reliably via HTTPS/mTLS.

### 2. Ingestion API (`backend/app/api/v1/endpoints/events.py`)
FastAPI application receiving agent events. Enforces tenant validation, token/mTLS authentication, payload size caps, and Redis-backed rate limits. Asynchronously publishes raw payloads to Kafka.

### 3. Event Bus (`Apache Kafka`)
Decouples ingestion from analysis. Guarantees event delivery across partitions using tenant keys and maintains dead-letter queues (`arka.events.dlq`) for unparseable data.

### 4. Normalization Engine (`backend/app/services/ingestion.py`)
Parses raw platform logs (e.g. Windows Event Code 4625 or Linux SSH auth failure) into standard ECS fields (`source_ip`, `user`, `event_type`, `severity`, `action`). Indexes normalized records into OpenSearch.

### 5. Storage Layer (`PostgreSQL` & `OpenSearch`)
- **PostgreSQL**: System of record for tenants, users, RBAC roles, detection rules, alert lifecycle, incidents, and audit trails.
- **OpenSearch**: Time-series search index optimized for high-volume log storage, full-text queries, and aggregation.

### 6. Detection Engine (`backend/app/services/detection_engine.py`)
Stateful evaluator running against event streams. Evaluates sliding time-window thresholds (e.g. 5 failed logons within 300s) maintained in Redis, generates alerts mapped to MITRE ATT&CK techniques, and creates incidents.

### 7. SOC Dashboard UI (`frontend/`)
React/TypeScript single-page application providing security analysts with real-time operational visibility, event exploration capabilities, alert management, and incident triage.
