# Project: ARKA Enterprise SIEM & XDR Platform

## Architecture
- **Agent Subsystem (`agent/arka_agent/`)**: Daemon runtime, background collector scheduler, SQLiteQueue offline FIFO buffer, HTTP transport, telemetry harvesters (Rootcheck, SCA, Syscollector, FIM, Log collectors), and Active Response container.
- **Backend Subsystem (`backend/app/`)**: FastAPI async application, SQLAlchemy 2.x async ORM with PostgreSQL/SQLite, Pydantic schemas, Kafka event pipeline & normalization, OpenSearch ECS event indexer, and security services (SCA Engine, Inventory Service, Active Response Service, Vulnerability Engine).
- **Security & Integrity Model**: Zero fake data, real OS telemetry collection, real database persistence, strict safety guardrails for endpoint containment actions, comprehensive audit logging.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | DB Schema & Models (R2-R5) | 12 SQLAlchemy 2.x models for SCA, Syscollector, Active Response, and Vulnerability findings | M1 | Survey |
| 2 | Pydantic Schemas (R2-R5) | Full request/response data schemas for all new entities and endpoints | M1 | Survey |
| 3 | R1: Rootkit Artifact Scanner | Known rootkit artifact file & directory scanner (Linux Diamorphine, Reptile, Azazel; Windows driver/registry keys) | M2 | ORIGINAL_REQUEST §1 |
| 4 | R1: Hidden Process Harvester | Cross-validation of standard process lists against raw `/proc` filesystem and OS APIs | M2 | ORIGINAL_REQUEST §1 |
| 5 | R1: Backdoor & Promiscuous Socket Scanner | Detection of unmapped sockets, high-risk backdoor ports (31337, 6667, 4444), and promiscuous interfaces | M2 | ORIGINAL_REQUEST §1 |
| 6 | R1: System Binary & Preload Tampering | Audit of `/etc/ld.so.preload`, Windows AppInit_DLLs, and critical binary permissions | M2 | ORIGINAL_REQUEST §1 |
| 7 | R2: Multi-Platform CIS Evaluator Engine | Rule evaluator engine for file content regex, file permissions/ownership, Windows registry, safe command output | M3 | ORIGINAL_REQUEST §2 |
| 8 | R2: Linux & Windows CIS Benchmark Profiles | Standard CIS Benchmark rules (Linux v2.0, Windows Client/Server) for SSH, firewall, passwords, permissions | M3 | ORIGINAL_REQUEST §2 |
| 9 | R2: Compliance Scoring & Backend Service | Mathematical compliance calculation `(passed/(passed+failed)*100)`, PostgreSQL persistence, zero fake data | M3 | ORIGINAL_REQUEST §2 |
| 10 | R3: Installed Package Harvester | Native software package extraction (dpkg, rpm, apk, winreg, python modules) with zero fake data | M4 | ORIGINAL_REQUEST §3 |
| 11 | R3: Network Interfaces & Port Harvester | Detailed network adapter inventory and listening socket / connection enumeration | M4 | ORIGINAL_REQUEST §3 |
| 12 | R3: Hardware, OS & Process Harvester | Complete hardware stats, OS kernel metadata, and running process table with lineage metadata | M4 | ORIGINAL_REQUEST §3 |
| 13 | R3: Inventory REST APIs & Persistence | Canonical relational tables for all inventory components and sub-resource query endpoints | M4 | ORIGINAL_REQUEST §3 |
| 14 | R4: Safe Firewall IP Blocking | OS firewall containment (`iptables`/`netsh`) with strict IP allowlist protection and timed rollback | M5 | ORIGINAL_REQUEST §4 |
| 15 | R4: Safe Process Termination | Two-phase process termination (SIGTERM -> SIGKILL) with protected system PID allowlist | M5 | ORIGINAL_REQUEST §4 |
| 16 | R4: Secure File Quarantine Vault | Restricted access quarantine vault with SHA256 manifest tracking and unquarantine restore | M5 | ORIGINAL_REQUEST §4 |
| 17 | R4: Active Response Backend Service | Task lifecycle tracking (`PENDING`->`SUCCESS`/`FAILED`), automated alert trigger, agent callback | M5 | ORIGINAL_REQUEST §4 |
| 18 | R5: Semantic Version CVE Correlation | Semantic version comparison (`packaging.version`), NVD CVE database matching | M6 | ORIGINAL_REQUEST §5 |
| 19 | R5: CVSS Scoring & Severity Metrics | CVSS v3 score calculation, CWE classification, vulnerability count tallies, remediation guidance | M6 | ORIGINAL_REQUEST §5 |
| 20 | R5: Vulnerability Finding Lifecycle | Database persistence of findings (`ACTIVE`->`MITIGATED`->`RESOLVED`), automated trigger on inventory ingest | M6 | ORIGINAL_REQUEST §5 |
| 21 | Final Acceptance & Quality Gates | 100% pass on all test tiers, 0 ruff errors, 0 mypy type errors, 0 bandit security issues, clean forensic audit | M7 | ORIGINAL_REQUEST Acceptance |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Core DB Models & Schemas | Add 12 SQLAlchemy models and Pydantic schemas for R2-R5 in `models.py` and `schemas.py` | None | DONE |
| M2 | R1: Rootcheck & Anomaly Harvester | Implement `agent/arka_agent/collectors/rootcheck.py` with comprehensive anomaly detection | None | DONE |
| M3 | R2: SCA & CIS Benchmarks Engine | Implement `agent/arka_agent/collectors/sca.py`, `backend/app/services/sca_engine.py`, `backend/app/api/v1/endpoints/sca.py` | M1 | IN_PROGRESS |
| M4 | R3: Syscollector & Inventory APIs | Implement `agent/arka_agent/collectors/syscollector.py`, `backend/app/services/inventory_service.py`, `backend/app/api/v1/endpoints/inventory.py` | M1 | IN_PROGRESS |
| M5 | R4: Active Response Container & Service | Implement `agent/arka_agent/active_response.py`, `backend/app/services/active_response_service.py`, `backend/app/api/v1/endpoints/active_response.py` | M1 | PLANNED |
| M6 | R5: Vulnerability & CVE Engine | Implement `backend/app/services/vulnerability_engine.py`, `backend/app/api/v1/endpoints/vulnerabilities.py`, package correlation | M1, M4 | PLANNED |
| M7 | Final E2E Suite & Hardening | Pass 100% of E2E tests (Tiers 1-4), Tier 5 adversarial hardening, zero fake data audit, ruff, mypy, bandit | M1-M6 | PLANNED |

## Code Layout
- `backend/app/models/models.py`: All SQLAlchemy 2.x declarative database models
- `backend/app/schemas/schemas.py`: All Pydantic validation and serialization schemas
- `backend/app/services/sca_engine.py`: Backend SCA compliance evaluation service
- `backend/app/services/inventory_service.py`: Backend System inventory persistence and query service
- `backend/app/services/active_response_service.py`: Backend Active response dispatch and validation service
- `backend/app/services/vulnerability_engine.py`: Backend CVE correlation and CVSS scoring service
- `backend/app/api/v1/endpoints/`: FastAPI endpoint routers (`inventory.py`, `sca.py`, `active_response.py`, `vulnerabilities.py`, `events.py`)
- `agent/arka_agent/collectors/rootcheck.py`: R1 Rootcheck scanner
- `agent/arka_agent/collectors/sca.py`: R2 SCA CIS scanner
- `agent/arka_agent/collectors/syscollector.py`: R3 Syscollector inventory harvester
- `agent/arka_agent/active_response.py`: R4 Active response containment executor
- `agent/arka_agent/collectors/vulnerability.py`: R5 Agent vulnerability package scanner
- `backend/tests/`: Backend unit, service, API, and pipeline tests
- `agent/tests/`: Agent collector, queue, transport, and containment tests
