# ARKA — Advanced Real-time Kinetic Analytics

> **Turning the constant flow of digital events into security intelligence.**

[![CI Pipeline](https://github.com/AVII-VERSE/arka/actions/workflows/ci.yml/badge.svg)](https://github.com/AVII-VERSE/arka/actions/workflows/ci.yml)
[![Security Scan](https://github.com/AVII-VERSE/arka/actions/workflows/security.yml/badge.svg)](https://github.com/AVII-VERSE/arka/actions/workflows/security.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12%2B-blue)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-18-61dafb)](https://react.dev/)

---

## Overview

**ARKA (Advanced Real-time Kinetic Analytics)** is an enterprise security event management and SIEM platform designed to continuously ingest, normalize, process, correlate, and analyze security telemetry across heterogeneous infrastructure (endpoints, servers, cloud services, and network devices).

ARKA processes high-velocity raw security logs into structured security intelligence:

$$\text{Raw Events} \longrightarrow \text{Signals} \longrightarrow \text{Detections} \longrightarrow \text{Alerts} \longrightarrow \text{Incidents} \longrightarrow \text{Actionable Security Intelligence}$$

---

## Key Features

- **Multi-Source Event Ingestion**: Ingest logs from Windows Event Logs, Linux syslog/journald, and JSON application logs via high-throughput HTTP/mTLS endpoints.
- **Normalized Event Pipeline**: Standardized event format aligned with ECS (Elastic Common Schema) principles for cross-platform event correlation.
- **Streaming Event Bus**: Asynchronous, fault-tolerant processing powered by Apache Kafka with dedicated Dead Letter Queues (DLQ).
- **Deterministic Detection Engine**: Rule-based engine supporting threshold state, sliding time windows, dynamic conditions, and MITRE ATT&CK mapping.
- **Alert Correlation & Incident Engine**: Automatic alert aggregation into actionable multi-stage incidents with complete audit trails.
- **Professional SOC Interface**: Real-time operational dashboard with event rate meters, MITRE technique matrix, event explorer, and alert investigation workflows.
- **Strict Multi-Tenancy & RBAC**: Tenant-isolated event streams and role-based access controls (`SUPER_ADMIN`, `TENANT_ADMIN`, `SECURITY_ANALYST`, `SECURITY_VIEWER`).
- **Resilient Endpoint Agent**: Lightweight Python daemon supporting local SQLite buffering for offline resilience and automatic server reconnects.

---

## System Architecture

```
                          ┌───────────────────────────┐
                          │    Endpoints / Servers    │
                          │ (Windows / Linux Collectors)│
                          └─────────────┬─────────────┘
                                        │ mTLS / REST API
                                        ▼
                          ┌───────────────────────────┐
                          │    ARKA Ingestion API     │ (FastAPI)
                          └─────────────┬─────────────┘
                                        │ Produce Raw Events
                                        ▼
                          ┌───────────────────────────┐
                          │       Apache Kafka        │
                          │   (arka.events.raw)       │
                          └─────────────┬─────────────┘
                                        │ Consume & Normalize
                                        ▼
                          ┌───────────────────────────┐
                          │ Event Normalizer Engine   │
                          └──────┬──────────────┬─────┘
                                 │              │
                    OpenSearch   │              │ PostgreSQL
                                 ▼              ▼
                     ┌───────────────┐      ┌─────────────────┐
                     │ Normalized    │      │ Multi-Tenant    │
                     │ Event Storage │      │ Metadata & Rules│
                     └───────┬───────┘      └────────┬────────┘
                             │                       │
                             ▼                       ▼
                     ┌────────────────────────────────┐
                     │  ARKA Detection & Correlation  │
                     │             Engine             │
                     └───────────────┬────────────────┘
                                     │ Produce Alerts
                                     ▼
                     ┌────────────────────────────────┐
                     │   Incident Management & SOC    │
                     │         Dashboard UI           │
                     └────────────────────────────────┘
```

---

## Event Pipeline

1. **Collection**: ARKA Agent captures system telemetry (authentication events, process execution, service state).
2. **Ingestion**: `POST /api/v1/events/ingest` validates schema, authenticates agent certificates/tokens, and enforces tenant rate limits.
3. **Buffering**: Raw payloads publish asynchronously to Kafka topic `arka.events.raw`.
4. **Normalization & Enrichment**: Normalizer consumes raw events, applies standardized timestamp parsing, extracts IP/user/process metadata, and writes to tenant-isolated OpenSearch indices (`arka-events-{tenant}-{yyyy.mm}`).
5. **Detection Evaluation**: Real-time evaluator checks stateful rules against sliding event windows stored in Redis.
6. **Alerting & Incidents**: Triggered detections publish to `arka.alerts` topic, persist to PostgreSQL, and trigger incident correlation logic.
7. **SOC Investigation**: Analysts triage alerts in the SOC Dashboard, mutate lifecycle states (`NEW` $\rightarrow$ `INVESTIGATING` $\rightarrow$ `RESOLVED`), and generate audit logs.

---

## Technology Stack

| Layer | Technology |
|---|---|
| **Backend API** | Python 3.12+, FastAPI, Pydantic v2, SQLAlchemy 2.x (Async), Alembic |
| **Event Bus** | Apache Kafka |
| **Search & Indexing** | OpenSearch 2.x |
| **Caching / State** | Redis 7.x |
| **Database** | PostgreSQL 16 |
| **Agent** | Python 3.12+ (Windows / Linux cross-platform daemon, SQLite local queue) |
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, Recharts, TanStack Query |
| **Authentication** | OAuth 2.0 / OIDC (Keycloak), JWT, mTLS |
| **Infrastructure** | Docker, Docker Compose, Nginx |
| **Testing** | Pytest, HTTPX, Vitest, React Testing Library, Playwright |
| **Security Scanning** | Bandit, pip-audit, Trivy, Semgrep |

---

## Repository Structure

```
arka/
├── backend/            # FastAPI backend, DB models, ingestion API, Kafka services
├── agent/              # Endpoint collector daemon & offline SQLite queue
├── frontend/           # React + TypeScript + Vite SOC Dashboard
├── detection-rules/    # YAML deterministic security detection rules
├── infrastructure/     # Nginx, Docker Compose, OpenSearch mapping configs
├── docs/               # System architecture & developer documentation
├── tests/              # End-to-end (Playwright) & synthetic event generators
├── .github/            # CI/CD workflows, issue templates, PR templates
├── docker-compose.yml  # Local multi-container development environment
└── README.md           # Project documentation
```

---

## Quick Start (Local Development)

### Prerequisites

- **Docker** & **Docker Compose v2**
- **Python 3.12+**
- **Node.js 20+** & **npm 10+**

### 1. Clone the Repository

```bash
git clone https://github.com/AVII-VERSE/arka.git
cd arka
```

### 2. Configure Environment

```bash
cp .env.example .env
```

### 3. Launch Infrastructure Services

```bash
docker compose up -d
```

This starts PostgreSQL, Kafka, OpenSearch, Redis, and Keycloak.

### 4. Run Backend Server

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

### 5. Launch SOC Dashboard

```bash
cd ../frontend
npm install
npm run dev
```

Navigate to `http://localhost:5173` to access the ARKA SOC Dashboard.

---

## Example Normalized Event Payload

```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "tenant_id": "tenant-corp-alpha",
  "agent_id": "agent-win-01",
  "timestamp": "2026-08-19T10:35:00.000Z",
  "source_type": "windows_event_log",
  "host": "DC01.corp.internal",
  "source_ip": "192.168.1.105",
  "destination_ip": "192.168.1.10",
  "user": "Administrator",
  "event_type": "authentication",
  "action": "logon_failed",
  "severity": "MEDIUM",
  "message": "An account failed to log on. Logon Type: 3. Status: 0xC00006D.",
  "process": "C:\\Windows\\System32\\lsass.exe",
  "metadata": {
    "event_code": 4625,
    "logon_type": 3,
    "workstation_name": "WORKSTATION-84"
  },
  "ingested_at": "2026-08-19T10:35:01.120Z"
}
```

---

## Detection Rule Example

```yaml
id: rule-brute-force-login
name: Multiple Failed Authentication Attempts (Brute Force)
description: Detects more than 5 failed logon attempts from the same source IP within 5 minutes.
severity: HIGH
enabled: true
tenant_id: default
mitre_attack:
  tactic: Credential Access
  technique_id: T1110
  technique_name: Brute Force
conditions:
  event_type: authentication
  action: logon_failed
threshold:
  count: 5
  time_window_seconds: 300
  group_by:
    - source_ip
    - user
```

---

## Testing & Quality Assurance

Run the test suite across all components:

```bash
# Backend unit & integration tests
cd backend && pytest

# Agent unit tests
cd agent && pytest

# Frontend unit tests
cd frontend && npm test

# Security scanning
bandit -r backend/app
pip-audit
```

---

## Security Policy

Security vulnerabilities should be disclosed responsibly. Please review our [SECURITY.md](SECURITY.md) for details on security reporting processes and bug bounty disclosures.

---

## Contributing

We welcome contributions from security engineers, backend developers, and UI designers. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and our [Branching Strategy](docs/development/branching-strategy.md) before submitting Pull Requests.

---

## License

ARKA is licensed under the [Apache License 2.0](LICENSE).
